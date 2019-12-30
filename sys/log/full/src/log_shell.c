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

/* This whole file is conditionally compiled based on whether the
 * log package is configured to use the shell (MYNEWT_VAL(LOG_CLI)).
 */

#if MYNEWT_VAL(LOG_CLI)

#include <stdio.h>
#include <string.h>

#include "cbmem/cbmem.h"
#include "log/log.h"
#if MYNEWT_VAL(LOG_FCB_SLOT1)
#include "log/log_fcb_slot1.h"
#endif
#include "shell/shell.h"
#include "console/console.h"
#include "base64/hex.h"
#if MYNEWT_VAL(LOG_VERSION) > 2
#include "tinycbor/cbor.h"
#include "tinycbor/compilersupport_p.h"
#include "log_cbor_reader/log_cbor_reader.h"
#endif

static int
shell_log_dump_entry(struct log *log, struct log_offset *log_offset,
                     const struct log_entry_hdr *ueh, const void *dptr, uint16_t len)
{
    char data[128 + 1];
    int dlen;
    int rc = 0;
#if MYNEWT_VAL(LOG_VERSION) > 2
    struct CborParser cbor_parser;
    struct CborValue cbor_value;
    struct log_cbor_reader cbor_reader;
    char tmp[32 + 1];
    int off;
    int blksz;
    bool read_data = ueh->ue_etype != LOG_ETYPE_CBOR;
    bool read_hash = ueh->ue_flags & LOG_FLAGS_IMG_HASH;
#else
    bool read_data = true;
#endif

    dlen = min(len, 128);

    if (read_data) {
        rc = log_read_body(log, dptr, data, 0, dlen);
        if (rc < 0) {
            return rc;
        }
        data[rc] = 0;
    }

#if MYNEWT_VAL(LOG_VERSION) > 2
    if (read_hash) {
        console_printf("[ih=0x%x%x%x%x]", ueh->ue_imghash[0], ueh->ue_imghash[1],
                       ueh->ue_imghash[2], ueh->ue_imghash[3]);
    }
    console_printf(" [%llu] ", ueh->ue_ts);
#endif

#if MYNEWT_VAL(LOG_VERSION) <= 2
    console_write(data, strlen(data));
#else
    switch (ueh->ue_etype) {
    case LOG_ETYPE_STRING:
        console_write(data, strlen(data));
        break;
    case LOG_ETYPE_CBOR:
        log_cbor_reader_init(&cbor_reader, log, dptr, len);
        cbor_parser_init(&cbor_reader.r, 0, &cbor_parser, &cbor_value);
        cbor_value_to_pretty(stdout, &cbor_value);
        break;
    default:
        for (off = 0; off < rc; off += blksz) {
            blksz = dlen - off;
            if (blksz > sizeof(tmp) >> 1) {
                blksz = sizeof(tmp) >> 1;
            }
            hex_format(&data[off], blksz, tmp, sizeof(tmp));
            console_write(tmp, strlen(tmp));
        }
        if (rc < len) {
            console_write("...", 3);
        }
    }
#endif

    console_write("\n", 1);
    return 0;
}

int
shell_log_dump_cmd(int argc, char **argv)
{
    struct log *log;
    struct log_offset log_offset;
    bool last = false;
    bool list_only;
    int rc;

    list_only = ((argc > 1) && !strcmp(argv[1], "-l"));

    log = NULL;
    do {
        log = log_list_get_next(log);
        if (log == NULL) {
            break;
        }

        if (log->l_log->log_type == LOG_TYPE_STREAM) {
            continue;
        }

        if (list_only) {
            console_printf("%s\n", log->l_name);
            continue;
        }

        if (argc > 1) {
            if (strcmp(log->l_name, argv[1])) {
                continue;
            }
            last = true;
        }

        console_printf("Dumping log %s\n", log->l_name);

        log_offset.lo_arg = NULL;
        log_offset.lo_ts = 0;
        log_offset.lo_index = 0;
        log_offset.lo_data_len = 0;

        rc = log_walk_body(log, shell_log_dump_entry, &log_offset);
        if (rc != 0) {
            goto err;
        }
    } while (!last);

    return (0);
err:
    return (rc);
}

#if MYNEWT_VAL(LOG_FCB_SLOT1)
int
shell_log_slot1_cmd(int argc, char **argv)
{
    const struct flash_area *fa;
    int rc;

    if (argc == 1) {
        console_printf("slot1 state is: %s\n",
                       log_fcb_slot1_is_locked() ? "locked" : "unlocked");
    } else {
        if (!strcasecmp(argv[1], "lock")) {
            log_fcb_slot1_lock();
            console_printf("slot1 locked\n");
        } else if (!strcasecmp(argv[1], "unlock")) {
            log_fcb_slot1_unlock();
            console_printf("slot1 unlocked\n");
        } else if (!strcasecmp(argv[1], "erase")) {
            rc = flash_area_open(FLASH_AREA_IMAGE_1, &fa);
            if (rc) {
                return -1;
            }

            flash_area_erase(fa, 0, fa->fa_size);

            console_printf("slot1 erased\n");
        } else {
            return -1;
        }
    }

    return 0;
}
#endif

#if MYNEWT_VAL(LOG_STORAGE_INFO)
int
shell_log_storage_cmd(int argc, char **argv)
{
    struct log *log;
    struct log_storage_info info;

    log = NULL;
    while (1) {
        log = log_list_get_next(log);
        if (log == NULL) {
            break;
        }

        if (log->l_log->log_type == LOG_TYPE_STREAM) {
            continue;
        }

        if (log_storage_info(log, &info)) {
            console_printf("Storage info not supported for %s\n", log->l_name);
        } else {
            console_printf("%s: %d of %d used\n", log->l_name,
                           (unsigned)info.used, (unsigned)info.size);
#if MYNEWT_VAL(LOG_STORAGE_WATERMARK)
            console_printf("%s: %d of %d used by unread entries\n", log->l_name,
                           (unsigned)info.used_unread, (unsigned)info.size);
#endif
        }
    }

    return (0);
}
#endif

#endif
