/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "os/mynewt.h"
#include "console/console.h"
#include "console_priv.h"

/* Indicates whether the previous line of output was completed. */
int console_is_midline;
uint8_t g_is_output_nlip;

#define CONSOLE_NLIP_PKT_START1 (6)
#define CONSOLE_NLIP_PKT_START2 (9)
#define CONSOLE_NLIP_DATA_START1 (4)
#define CONSOLE_NLIP_DATA_START2 (20)

#define NLIP_PKT_START1  (1 << 0)
#define NLIP_PKT_START2  (1 << 1)
#define NLIP_DATA_START1 (1 << 2)
#define NLIP_DATA_START2 (1 << 3)

#if MYNEWT_VAL(CONSOLE_COMPAT)
#define CONSOLE_COMPAT_MAX_CMD_QUEUED 1
static struct console_input buf[CONSOLE_COMPAT_MAX_CMD_QUEUED];
static struct os_event shell_console_ev[CONSOLE_COMPAT_MAX_CMD_QUEUED];
static console_rx_cb console_compat_rx_cb; /* callback that input is ready */
static struct os_eventq compat_avail_queue;
static struct os_eventq compat_lines_queue;
#endif

static int nlip_state;
static int echo = MYNEWT_VAL(CONSOLE_ECHO);

static uint8_t cur, end;
static struct os_eventq *avail_queue;
static struct os_eventq *lines_queue;
bool g_console_silence;
bool g_console_silence_non_nlip;
bool g_console_ignore_non_nlip;
static struct os_mutex console_write_lock;

int __attribute__((weak))
console_out_nolock(int c)
{
    return c;
}

void
console_echo(int on)
{
    echo = on;
}

int
console_lock(int timeout)
{
    int rc = OS_OK;

    /* Locking from isr while some task own mutex fails with OS_EBUSY */
    if (os_arch_in_isr()) {
        if (os_mutex_get_level(&console_write_lock)) {
            rc = OS_EBUSY;
        }
        goto end;
    }

    rc = os_mutex_pend(&console_write_lock, timeout);
    if (rc == OS_NOT_STARTED) {
        /* No need to block before system start make it OK */
        rc = OS_OK;
    }

end:
    return rc;
}

int
console_unlock(void)
{
    int rc = OS_OK;

    if (os_arch_in_isr()) {
        goto end;
    }

    rc = os_mutex_release(&console_write_lock);
    assert(rc == OS_OK || rc == OS_NOT_STARTED);
end:
    return rc;
}

int
console_out(int c)
{
    int rc;
    const os_time_t timeout =
            os_time_ms_to_ticks32(MYNEWT_VAL(CONSOLE_DEFAULT_LOCK_TIMEOUT));

    if (console_lock(timeout) != OS_OK) {
        return c;
    }
    rc = console_out_nolock(c);

    (void)console_unlock();

    return rc;
}

void
console_prompt_set(const char *prompt, const char *line)
{
    console_write(prompt, strlen(prompt));
    if (line) {
        console_write(line, strlen(line));
    }
}

void
console_write(const char *str, int cnt)
{
    int i;
    const os_time_t timeout =
            os_time_ms_to_ticks32(MYNEWT_VAL(CONSOLE_DEFAULT_LOCK_TIMEOUT));

    if (console_lock(timeout) != OS_OK) {
        return;
    }

    if (cnt >= 2 && str[0] == CONSOLE_NLIP_DATA_START1 &&
        str[1] == CONSOLE_NLIP_DATA_START2) {
        g_is_output_nlip = 1;
    }

    /* From the shell the first byte is always \n followed by the
     * actual pkt start bytes, hence checking byte 1 and 2
     */
    if (cnt >= 3 && str[1] == CONSOLE_NLIP_PKT_START1 &&
        str[2] == CONSOLE_NLIP_PKT_START2) {
        g_is_output_nlip = 1;
    }


    /* If the byte string is non nlip and we are silencing non nlip bytes,
     * do not let it go out on the console
     */ 
    if (!g_is_output_nlip && g_console_silence_non_nlip) {
        goto done;
    }

    for (i = 0; i < cnt; i++) {
        if (console_out_nolock((int)str[i]) == EOF) {
            break;
        }
    }

done:
    if (cnt > 0 && str[cnt - 1] == '\n') {
        g_is_output_nlip = 0;
    }
    (void)console_unlock();
}

#if MYNEWT_VAL(CONSOLE_COMPAT)
int
console_read(char *str, int cnt, int *newline)
{
    struct os_event *ev;
    struct console_input *cmd;
    size_t len;

    *newline = 0;
    ev = os_eventq_get_no_wait(lines_queue);
    if (!ev) {
        return 0;
    }
    cmd = ev->ev_arg;
    len = strlen(cmd->line);
    if ((cnt - 1) < len) {
        len = cnt - 1;
    }

    if (len > 0) {
        memcpy(str, cmd->line, len);
        str[len] = '\0';
    } else {
        str[0] = cmd->line[0];
    }

    os_eventq_put(avail_queue, ev);
    *newline = 1;
    return len;
}
#endif

void
console_blocking_mode(void)
{
#if MYNEWT_VAL(CONSOLE_UART)
    uart_console_blocking_mode();
#endif
}

void
console_non_blocking_mode(void)
{
#if MYNEWT_VAL(CONSOLE_UART)
    uart_console_non_blocking_mode();
#endif
}

static void
insert_char(char *pos, char c, uint8_t end)
{
    if (cur + end >= MYNEWT_VAL(CONSOLE_MAX_INPUT_LEN) - 1) {
        return;
    }

    if (echo) {
        /* Echo back to console */
        console_out(c);
    }

    ++cur;
    *pos = c;
    return;

}

static int
handle_nlip(uint8_t byte)
{
    if (((nlip_state & NLIP_PKT_START1) &&
         (nlip_state & NLIP_PKT_START2)) ||
        ((nlip_state & NLIP_DATA_START1) &&
         (nlip_state & NLIP_DATA_START2)))
    {
        return 1;
    }

    if ((nlip_state & NLIP_PKT_START1) &&
        (byte == CONSOLE_NLIP_PKT_START2)) {
        nlip_state |= NLIP_PKT_START2;
        return 1;
    } else if ((nlip_state & NLIP_DATA_START1) &&
               (byte == CONSOLE_NLIP_DATA_START2)) {
        nlip_state |= NLIP_DATA_START2;
        return 1;
    } else {
        nlip_state = 0;
        return 0;
    }
}

int
console_handle_char(uint8_t byte)
{
#if !MYNEWT_VAL(CONSOLE_INPUT)
    return 0;
#endif

    static struct os_event *ev;
    static struct console_input *input;
    static char prev_endl = '\0';

    if (!avail_queue || !lines_queue) {
        return 0;
    }

    if (!ev) {
        ev = os_eventq_get_no_wait(avail_queue);
        if (!ev)
            return 0;
        input = ev->ev_arg;
    }

    if (handle_nlip(byte))  {
        if (byte == '\n') {
            insert_char(&input->line[cur], byte, end);
            input->line[cur] = '\0';
            cur = 0;
            end = 0;
            os_eventq_put(lines_queue, ev);
            nlip_state = 0;

#if MYNEWT_VAL(CONSOLE_COMPAT)
            if (console_compat_rx_cb) {
                console_compat_rx_cb();
            }
#endif

            input = NULL;
            ev = NULL;
            console_echo(1);
            return 0;
        /* Ignore characters if there's no more buffer space */
        } else if (byte == CONSOLE_NLIP_PKT_START2) {
            /* Disable echo to not flood the UART */
            console_echo(0);
            insert_char(&input->line[cur], CONSOLE_NLIP_PKT_START1, end);
        } else if (byte == CONSOLE_NLIP_DATA_START2) {
            /* Disable echo to not flood the UART */
            console_echo(0);
            insert_char(&input->line[cur], CONSOLE_NLIP_DATA_START1, end);
        }

        insert_char(&input->line[cur], byte, end);

        return 0;
    }

    /* Handle special control characters */
    if (!isprint(byte)) {
        switch (byte) {
        case CONSOLE_NLIP_PKT_START1:
            nlip_state |= NLIP_PKT_START1;
            break;
        case CONSOLE_NLIP_DATA_START1:
            nlip_state |= NLIP_DATA_START1;
            break;
        default:
            insert_char(&input->line[cur], byte, end);
            /* Falls through. */
        case '\r':
            /* Falls through. */
        case '\n':
            if (byte == '\n' && prev_endl == '\r') {
                /* handle double end line chars */
                prev_endl = byte;
                break;
            }
            prev_endl = byte;
            input->line[cur + end] = '\0';
            console_out('\r');
            console_out('\n');
            cur = 0;
            end = 0;
            os_eventq_put(lines_queue, ev);

#if MYNEWT_VAL(CONSOLE_COMPAT)
            if (console_compat_rx_cb) {
                console_compat_rx_cb();
            }
#endif

            input = NULL;
            ev = NULL;
            break;
        }

        return 0;
    }

    /* Ignore characters if there's no more buffer space */
    if ((cur + end < sizeof(input->line) - 1) &&
        (!g_console_ignore_non_nlip)) {
        insert_char(&input->line[cur], byte, end);
    }
    return 0;
}

int
console_is_init(void)
{
#if MYNEWT_VAL(CONSOLE_UART)
    return uart_console_is_init();
#endif
#if MYNEWT_VAL(CONSOLE_RTT)
    return rtt_console_is_init();
#endif
    return 0;
}

void
console_set_queues(struct os_eventq *avail, struct os_eventq *lines)
{
    avail_queue = avail;
    lines_queue = lines;
}

#if MYNEWT_VAL(CONSOLE_COMPAT)
int
console_init(console_rx_cb rx_cb)
{
    int i;

    os_eventq_init(&compat_lines_queue);
    os_eventq_init(&compat_avail_queue);
    console_set_queues(&compat_avail_queue, &compat_lines_queue);

    for (i = 0; i < CONSOLE_COMPAT_MAX_CMD_QUEUED; i++) {
        shell_console_ev[i].ev_arg = &buf[i];
        os_eventq_put(avail_queue, &shell_console_ev[i]);
    }
    console_compat_rx_cb = rx_cb;
    return 0;
}
#endif

void
console_pkg_init(void)
{
    int rc = 0;

    /* Ensure this function only gets called by sysinit. */
    SYSINIT_ASSERT_ACTIVE();

#if MYNEWT_VAL(CONSOLE_UART)
    rc = uart_console_init();
#endif
#if MYNEWT_VAL(CONSOLE_RTT)
    rc = rtt_console_init();
#endif
    SYSINIT_PANIC_ASSERT(rc == 0);
}
