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
#include <stddef.h>

#include "fcb/fcb2.h"
#include "fcb_priv.h"
#include "crc/crc8.h"

int
fcb2_new_sector(struct fcb2 *fcb, int cnt)
{

    int new_sector = -1;
    int sector = fcb->f_active.fe_sector;

    do {
        sector = fcb2_getnext_sector(fcb, sector);
        if (new_sector < 0) {
            new_sector = sector;
        }
        if (sector == fcb->f_oldest_sec) {
            new_sector = -1;
            break;
        }
    } while (--cnt >= 0);

    return new_sector;
}

/*
 * Take one of the scratch blocks into use, if at all possible.
 */
int
fcb2_append_to_scratch(struct fcb2 *fcb)
{
    int sector;
    int rc;
    struct flash_sector_range *range;

    sector = fcb2_new_sector(fcb, 0);
    if (sector < 0) {
        return FCB2_ERR_NOSPACE;
    }
    rc = fcb2_sector_hdr_init(fcb, sector, fcb->f_active_id + 1);
    if (rc) {
        return rc;
    }
    range = fcb2_get_sector_range(fcb, sector);
    fcb->f_active.fe_range = range;
    fcb->f_active.fe_sector = sector;
    fcb->f_active.fe_data_off =
        fcb2_len_in_flash(range, sizeof(struct fcb2_disk_area));
    fcb->f_active.fe_entry_num = 1;
    fcb->f_active_id++;
    return FCB2_OK;
}

static inline int
fcb2_sector_flash_offset(const struct fcb2_entry *loc)
{
    return (loc->fe_sector - loc->fe_range->fsr_first_sector) *
        loc->fe_range->fsr_sector_size;
}

int
fcb2_write_to_sector(struct fcb2_entry *loc, int off, const void *buf, int len)
{
    /* For negative offsets write from the end of sector */
    if (off < 0) {
        off += loc->fe_range->fsr_sector_size;
    }
    /* Truncate writes beyond sector */
    if (off + len > loc->fe_range->fsr_sector_size) {
        len = loc->fe_range->fsr_sector_size - off;
    }
    return flash_area_write(&loc->fe_range->fsr_flash_area,
        fcb2_sector_flash_offset(loc) + off, buf, len);
}

int
fcb2_read_from_sector(struct fcb2_entry *loc, int off, void *buf, int len)
{
    /* For negative offsets read from the end of sector */
    if (off < 0) {
        off += loc->fe_range->fsr_sector_size;
    }
    /* Truncate read beyond sector */
    if (off + len > loc->fe_range->fsr_sector_size) {
        len = loc->fe_range->fsr_sector_size - off;
    }
    return flash_area_read(&loc->fe_range->fsr_flash_area,
        fcb2_sector_flash_offset(loc) + off, buf, len);
}

int
fcb2_entry_location_in_range(const struct fcb2_entry *loc)
{
    const struct flash_sector_range *range = loc->fe_range;

    return range->fsr_sector_size *
        (1 + loc->fe_sector - range->fsr_first_sector) -
        (loc->fe_entry_num * fcb2_len_in_flash(loc->fe_range, FCB2_ENTRY_SIZE));
}

int
fcb2_active_sector_free_space(const struct fcb2 *fcb)
{
    const struct fcb2_entry *active = &fcb->f_active;
    const struct flash_sector_range *range = active->fe_range;

    return range->fsr_sector_size - active->fe_data_off -
        (active->fe_entry_num * fcb2_len_in_flash(range, FCB2_ENTRY_SIZE));
}

int
fcb2_write(struct fcb2_entry *loc, uint16_t off, const void *buf, uint16_t len)
{
    int pos = loc->fe_data_off + off;

    /* Make sure tha write does not exceed lenght declared in fcb2_append */
    if (off + len > loc->fe_data_len) {
        len = loc->fe_data_len - off;
    }
    return fcb2_write_to_sector(loc, pos, buf, len);
}

int
fcb2_read(struct fcb2_entry *loc, uint16_t off, void *buf, uint16_t len)
{
    int pos = loc->fe_data_off + off;

    /* Make sure that read is only from entry data */
    if (off + len > loc->fe_data_len) {
        len = loc->fe_data_len - off;
    }
    return fcb2_read_from_sector(loc, pos, buf, len);
}

int
fcb2_element_length_in_flash(const struct fcb2_entry *loc, int len)
{
    return fcb2_len_in_flash(loc->fe_range, len) +
        fcb2_len_in_flash(loc->fe_range, FCB2_CRC_LEN);
}

int
fcb2_append(struct fcb2 *fcb, uint16_t len, struct fcb2_entry *append_loc)
{
    struct fcb2_entry *active;
    struct flash_sector_range *range;
    uint8_t flash_entry[FCB2_ENTRY_SIZE];
    int sector;
    int rc;

    if (len == 0 || len >= FCB2_MAX_LEN) {
        return FCB2_ERR_ARGS;
    }

    rc = os_mutex_pend(&fcb->f_mtx, OS_WAIT_FOREVER);
    if (rc && rc != OS_NOT_STARTED) {
        return FCB2_ERR_ARGS;
    }
    active = &fcb->f_active;
    if (fcb2_active_sector_free_space(fcb) < fcb2_element_length_in_flash(active,
                                                                          len)) {
        sector = fcb2_new_sector(fcb, fcb->f_scratch_cnt);
        if (sector >= 0) {
            range = fcb2_get_sector_range(fcb, sector);
        }
        if (sector < 0 || (range->fsr_sector_size <
            fcb2_len_in_flash(range, sizeof(struct fcb2_disk_area)) +
            fcb2_len_in_flash(range, len) +
            fcb2_len_in_flash(range, FCB2_CRC_LEN))) {
            rc = FCB2_ERR_NOSPACE;
            goto err;
        }
        rc = fcb2_sector_hdr_init(fcb, sector, fcb->f_active_id + 1);
        if (rc) {
            goto err;
        }
        fcb->f_active.fe_range = range;
        fcb->f_active.fe_sector = sector;
        /* Start with offset just after sector header */
        fcb->f_active.fe_data_off =
            fcb2_len_in_flash(range, sizeof(struct fcb2_disk_area));
        /* No entries as yet */
        fcb->f_active.fe_entry_num = 1;
        fcb->f_active.fe_data_len = 0;
        fcb->f_active_id++;
    } else {
        range = active->fe_range;
    }

    /* Write new entry at the end of the sector */
    flash_entry[0] = (uint8_t)(fcb->f_active.fe_data_off >> 16);
    flash_entry[1] = (uint8_t)(fcb->f_active.fe_data_off >> 8);
    flash_entry[2] = (uint8_t)(fcb->f_active.fe_data_off >> 0);
    flash_entry[3] = (uint8_t)(len >> 8);
    flash_entry[4] = (uint8_t)(len >> 0);
    flash_entry[5] = crc8_calc(crc8_init(), flash_entry, FCB2_ENTRY_SIZE - 1);

    rc = fcb2_write_to_sector(active,
        active->fe_entry_num * -fcb2_len_in_flash(range, FCB2_ENTRY_SIZE),
        flash_entry, FCB2_ENTRY_SIZE);
    if (rc) {
        rc = FCB2_ERR_FLASH;
        goto err;
    }
    *append_loc = *active;
    /* Active element had everything ready except lenght */
    append_loc->fe_data_len = len;

    /* Prepare active element num and offset for new append */
    active->fe_data_off += fcb2_element_length_in_flash(active, len);
    active->fe_entry_num++;

    os_mutex_release(&fcb->f_mtx);

    return FCB2_OK;
err:
    os_mutex_release(&fcb->f_mtx);
    return rc;
}

int
fcb2_append_finish(struct fcb2_entry *loc)
{
    int rc;
    uint16_t crc;
    uint8_t fl_crc[2];
    uint32_t off;

    rc = fcb2_elem_crc16(loc, &crc);
    if (rc) {
        return rc;
    }
    put_be16(fl_crc, crc);
    off = loc->fe_data_off + fcb2_len_in_flash(loc->fe_range, loc->fe_data_len);

    rc = fcb2_write_to_sector(loc, off, fl_crc, sizeof(fl_crc));
    if (rc) {
        return FCB2_ERR_FLASH;
    }
    return 0;
}
