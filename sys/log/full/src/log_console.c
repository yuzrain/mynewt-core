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

#include "os/mynewt.h"

#if MYNEWT_VAL(LOG_CONSOLE)

#include <cbmem/cbmem.h>
#include <console/console.h>
#include "log/log.h"

static struct log log_console;

#if MYNEWT_VAL(LOG_CONSOLE_FORMATTER) == 1
#define LOG_CONSOLE_COLOR_DEFAULT   "\x1B[0m"
#if MYNEWT_VAL(LOG_CONSOLE_PRETTY_BRIGHT_COLORS)
#define LOG_CONSOLE_COLOR_RED       "\x1B[1;31m"
#define LOG_CONSOLE_COLOR_YELLOW    "\x1B[1;33m"
#define LOG_CONSOLE_COLOR_MAGENTA   "\x1B[1;35m"
#else
#define LOG_CONSOLE_COLOR_RED       "\x1B[31m"
#define LOG_CONSOLE_COLOR_YELLOW    "\x1B[33m"
#define LOG_CONSOLE_COLOR_MAGENTA   "\x1B[35m"
#endif

#define LOG_CONSOLE_LEVEL_DEF(_str, _color) \
    {                                       \
        .level_str = (_str),                \
        .color_seq = (_color),              \
    }

#define LOG_CONSOLE_LEVEL_DEF_MAX   \
    ((sizeof(log_console_level_defs) / sizeof(log_console_level_defs[0])) - 1)

struct log_console_level_def {
    const char *level_str;
    const char *color_seq;
};

static const struct log_console_level_def log_console_level_defs[] = {
    LOG_CONSOLE_LEVEL_DEF("D", LOG_CONSOLE_COLOR_DEFAULT),
    LOG_CONSOLE_LEVEL_DEF("I", LOG_CONSOLE_COLOR_DEFAULT),
    LOG_CONSOLE_LEVEL_DEF("W", LOG_CONSOLE_COLOR_YELLOW),
    LOG_CONSOLE_LEVEL_DEF("E", LOG_CONSOLE_COLOR_RED),
    LOG_CONSOLE_LEVEL_DEF("C", LOG_CONSOLE_COLOR_RED),
    LOG_CONSOLE_LEVEL_DEF("U", LOG_CONSOLE_COLOR_MAGENTA), /* unknown level */
};
#endif

struct log *
log_console_get(void)
{
    return &log_console;
}

#if MYNEWT_VAL(LOG_CONSOLE_FORMATTER) == 0
static void
log_console_write(const struct log_entry_hdr *hdr, const void *body, int length)
{
    if (!console_is_init()) {
        return;
    }

    if (!console_is_midline) {
        console_printf("[ts=%lluus, mod=%u level=%u] ", hdr->ue_ts,
                       hdr->ue_module, hdr->ue_level);
    }

    console_write(body, length);
}
#elif MYNEWT_VAL(LOG_CONSOLE_FORMATTER) == 1
static void
log_console_write(const struct log_entry_hdr *hdr, const void *body, int length)
{
    const struct log_console_level_def *def;
    const char *mod_name;
    int level;
    bool is_midline;

    if (!console_is_init()) {
        return;
    }

    level = min(hdr->ue_level, LOG_CONSOLE_LEVEL_DEF_MAX);
    def = &log_console_level_defs[level];

    is_midline = console_is_midline;

    if (!is_midline) {
#if MYNEWT_VAL(LOG_CONSOLE_PRETTY_TS_WIDTH) > 0
        console_printf("%s%0*llu ", def->color_seq,
                       MYNEWT_VAL(LOG_CONSOLE_PRETTY_TS_WIDTH),
                       hdr->ue_ts / MYNEWT_VAL(LOG_CONSOLE_PRETTY_TS_DIV));
#else
        console_printf("%s", def->color_seq);
#endif

        console_write_str(def->level_str);
        console_write_str("/");

        mod_name = log_module_get_name(hdr->ue_module);
        if (mod_name) {
            console_write_str(mod_name);
        } else {
            console_printf("%u", hdr->ue_module);
        }

#if MYNEWT_VAL(LOG_CONSOLE_PRETTY_USE_TASK_NAME)
        console_write_str(" (");
        console_write_str(os_sched_get_current_task()->t_name);
        console_write_str("): ");
#endif
    }

    if (((const char *)body)[length - 1] == '\n') {
        /*
         * Need to reset to default color before printing \n as otherwise escape
         * sequence would make console think it's mid-line.
         */
        console_write(body, length - 1);
        console_write_str(LOG_CONSOLE_COLOR_DEFAULT);
        console_write_str("\n");
    } else {
        console_write(body, length);
    }
}
#else
#error Unsupported console formatter selected.
#endif

static int
log_console_append(struct log *log, void *buf, int len)
{
    struct log_entry_hdr *hdr = (struct log_entry_hdr *) buf;
    const void *body = buf + LOG_ENTRY_HDR_SIZE;
    int body_len = len - LOG_ENTRY_HDR_SIZE;

    log_console_write(hdr, body, body_len);

    return 0;
}

static int
log_console_append_body(struct log *log, const struct log_entry_hdr *hdr,
                        const void *body, int body_len)
{
    log_console_write(hdr, body, body_len);

    return 0;
}

static int
log_console_read(struct log *log, void *dptr, void *buf, uint16_t offset,
        uint16_t len)
{
    /* You don't read console, console read you */
    return (OS_EINVAL);
}

static int
log_console_walk(struct log *log, log_walk_func_t walk_func,
        struct log_offset *log_offset)
{
    /* You don't walk console, console walk you. */
    return (OS_EINVAL);
}

static int
log_console_flush(struct log *log)
{
    /* You don't flush console, console flush you. */
    return (OS_EINVAL);
}

const struct log_handler log_console_handler = {
    .log_type = LOG_TYPE_STREAM,
    .log_read = log_console_read,
    .log_append = log_console_append,
    .log_append_body = log_console_append_body,
    .log_walk = log_console_walk,
    .log_flush = log_console_flush,
};

void
log_console_init(void)
{
    int rc;

    /* Ensure this function only gets called by sysinit. */
    SYSINIT_ASSERT_ACTIVE();

    rc = log_register("console", &log_console, &log_console_handler, NULL,
                      MYNEWT_VAL(LOG_LEVEL));
    SYSINIT_PANIC_ASSERT(rc == 0);
}

#endif
