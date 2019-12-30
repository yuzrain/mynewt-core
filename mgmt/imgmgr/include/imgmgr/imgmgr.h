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

#ifndef _IMGMGR_H_
#define _IMGMGR_H_

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMGMGR_NMGR_ID_STATE        0
#define IMGMGR_NMGR_ID_UPLOAD       1
#define IMGMGR_NMGR_ID_FILE         2
#define IMGMGR_NMGR_ID_CORELIST     3
#define IMGMGR_NMGR_ID_CORELOAD     4
#define IMGMGR_NMGR_ID_ERASE	    5
#define IMGMGR_NMGR_ID_ERASE_STATE  6

#define IMGMGR_NMGR_MAX_NAME		64
#define IMGMGR_NMGR_MAX_VER         25  /* 255.255.65535.4294967295\0 */

#define IMGMGR_HASH_LEN             32

#define IMGMGR_STATE_F_PENDING          0x01
#define IMGMGR_STATE_F_CONFIRMED        0x02
#define IMGMGR_STATE_F_ACTIVE           0x04
#define IMGMGR_STATE_F_PERMANENT        0x08

extern int boot_current_slot;

void imgmgr_module_init(void);

struct image_version;

/**
 * Parse version string in src, and fill in ver.
 */
int imgr_ver_parse(char *src, struct image_version *ver);

/**
 * Take version and convert it to string in dst.
 */
int imgr_ver_str(struct image_version *ver, char *dst);

/**
 * Returns version number of current image (if available).
 */
int imgr_my_version(struct image_version *ver);

/**
 * Read the current running image's build hash
 *
 * @param hash Ptr to hash to be filled up
 * @param hashlen Length of hash to return
 *
 * Returns -2 if either of the argument is 0 or NULL
 * Returns -1 if area is not readable
 * Returns 0 if image in slot is ok
 * Returns 1 if there is not a full image
 * Returns 2 if slot is empty
 */
int imgr_get_current_hash(uint8_t *hash, uint16_t hashlen);

int imgmgr_find_best_area_id(void);

/**
 * Reads image information
 *
 * @param  image_slot Slot to read image info from
 * @param  ver        Ptr to image version
 * @param  hash       Ptr to hash of the image read
 * @param  flags      Ptr to flags of the image read
 *
 * Returns -1 if area is not readable
 * Returns 0 if image in slot is ok
 * Returns 1 if there is not a full image
 * Returns 2 if slot is empty
 */
int imgr_read_info(int image_slot, struct image_version *ver, uint8_t *hash,
               uint32_t *flags);

/**
 * Get state flags from the requested image
 *
 * @param query_slot slot to query from
 *
 * @return 0 on success, non-zero on failure
 */
uint8_t imgmgr_state_flags(int query_slot);

/** @typedef imgr_upload_fn
 * @brief Application callback that is executed when an image upload request is
 * received.
 *
 * The callback's return code determines whether the upload request is accepted
 * or rejected.  If the callback returns 0, processing of the upload request
 * proceeds.  If the callback returns nonzero, the request is rejected with a
 * response containing an `rc` value equal to the return code.
 *
 * @param offset                The offset specified by the incoming request.
 * @param size                  The total size of the image being uploaded.
 * @param arg                   Optional argument specified when the callback
 *                                  was configured.
 *
 * @return                      0 if the upload request should be accepted;
 *                              nonzero to reject the request with the
 *                                  specified status.
 */
typedef int imgr_upload_fn(uint32_t offset, uint32_t size, void *arg);

/**
 * @brief Configures a callback that gets called whenever a valid image upload
 * request is received.
 *
 * The callback's return code determines whether the upload request is accepted
 * or rejected.  If the callback returns 0, processing of the upload request
 * proceeds.  If the callback returns nonzero, the request is rejected with a
 * response containing an `rc` value equal to the return code.
 *
 * @param cb                    The callback to execute on rx of an upload
 *                                  request.
 * @param arg                   Optional argument that gets passed to the
 *                                  callback.
 */
void imgr_set_upload_cb(imgr_upload_fn *cb, void *arg);

/** @brief Generic callback function for events */
typedef void (*imgmgr_dfu_cb)(void);

/** Callback function pointers */
typedef struct {
    imgmgr_dfu_cb dfu_started_cb;
    imgmgr_dfu_cb dfu_stopped_cb;
    imgmgr_dfu_cb dfu_pending_cb;
    imgmgr_dfu_cb dfu_confirmed_cb;
} imgmgr_dfu_callbacks_t;

/**
 * Register image manager callbacks
 *
 * @param cb_struct Ptr to callback struct
 */
void imgmgr_register_callbacks(const imgmgr_dfu_callbacks_t *cb_struct);

void imgmgr_dfu_stopped(void);
void imgmgr_dfu_started(void);
void imgmgr_dfu_pending(void);
void imgmgr_dfu_confirmed(void);

#ifdef __cplusplus
}
#endif

#endif /* _IMGMGR_H */
