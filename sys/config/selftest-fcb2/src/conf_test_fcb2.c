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

#include <stdio.h>
#include <string.h>

#include <os/mynewt.h>
#include <flash_map/flash_map.h>
#include <testutil/testutil.h>
#include <fcb/fcb2.h>
#include <config/config.h>
#include <config/config_fcb2.h>
#include <config_priv.h>
#include "conf_test_fcb2.h"

char val_string[CONF_TEST_FCB_VAL_STR_CNT][CONF_MAX_VAL_LEN];

uint8_t val8;
int c2_var_count = 1;

uint32_t val32;
uint64_t val64;

int test_get_called;
int test_set_called;
int test_commit_called;
int test_export_block;

char *ctest_handle_get(int argc, char **argv, char *val,
  int val_len_max);
int ctest_handle_set(int argc, char **argv, char *val);
int ctest_handle_commit(void);
int ctest_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt);
char *c2_handle_get(int argc, char **argv, char *val,
  int val_len_max);
int c2_handle_set(int argc, char **argv, char *val);
int c2_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt);
char *c3_handle_get(int argc, char **argv, char *val,
  int val_len_max);
int c3_handle_set(int argc, char **argv, char *val);
int c3_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt);

struct conf_handler config_test_handler = {
    .ch_name = "myfoo",
    .ch_get = ctest_handle_get,
    .ch_set = ctest_handle_set,
    .ch_commit = ctest_handle_commit,
    .ch_export = ctest_handle_export
};

char *
ctest_handle_get(int argc, char **argv, char *val, int val_len_max)
{
    test_get_called = 1;
    if (argc == 1 && !strcmp(argv[0], "mybar")) {
        return conf_str_from_value(CONF_INT8, &val8, val, val_len_max);
    }
    if (argc == 1 && !strcmp(argv[0], "mybar64")) {
        return conf_str_from_value(CONF_INT64, &val64, val, val_len_max);
    }
    return NULL;
}

int
ctest_handle_set(int argc, char **argv, char *val)
{
    uint8_t newval;
    uint64_t newval64;
    int rc;

    test_set_called = 1;
    if (argc == 1 && !strcmp(argv[0], "mybar")) {
        rc = CONF_VALUE_SET(val, CONF_INT8, newval);
        TEST_ASSERT(rc == 0);
        val8 = newval;
        return 0;
    }
    if (argc == 1 && !strcmp(argv[0], "mybar64")) {
        rc = CONF_VALUE_SET(val, CONF_INT64, newval64);
        TEST_ASSERT(rc == 0);
        val64 = newval64;
        return 0;
    }
    return OS_ENOENT;
}

int
ctest_handle_commit(void)
{
    test_commit_called = 1;
    return 0;
}

int
ctest_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt)
{
    char value[32];

    if (test_export_block) {
        return 0;
    }
    conf_str_from_value(CONF_INT8, &val8, value, sizeof(value));
    cb("myfoo/mybar", value);

    conf_str_from_value(CONF_INT64, &val64, value, sizeof(value));
    cb("myfoo/mybar64", value);

    return 0;
}

struct conf_handler c2_test_handler = {
    .ch_name = "2nd",
    .ch_get = c2_handle_get,
    .ch_set = c2_handle_set,
    .ch_commit = NULL,
    .ch_export = c2_handle_export
};

char *
c2_var_find(char *name)
{
    int idx = 0;
    int len;
    char *eptr;

    len = strlen(name);
    TEST_ASSERT(!strncmp(name, "string", 6));
    TEST_ASSERT(len > 6);

    idx = strtoul(&name[6], &eptr, 10);
    TEST_ASSERT(*eptr == '\0');
    TEST_ASSERT(idx < c2_var_count);
    return val_string[idx];
}

char *
c2_handle_get(int argc, char **argv, char *val, int val_len_max)
{
    int len;
    char *valptr;

    if (argc == 1) {
        valptr = c2_var_find(argv[0]);
        if (!valptr) {
            return NULL;
        }
        len = strlen(val_string[0]);
        if (len > val_len_max) {
            len = val_len_max;
        }
        strncpy(val, valptr, len);
    }
    return NULL;
}

int
c2_handle_set(int argc, char **argv, char *val)
{
    char *valptr;

    if (argc == 1) {
        valptr = c2_var_find(argv[0]);
        if (!valptr) {
            return OS_ENOENT;
        }
        if (val) {
            strncpy(valptr, val, sizeof(val_string[0]));
        } else {
            memset(valptr, 0, sizeof(val_string[0]));
        }
        return 0;
    }
    return OS_ENOENT;
}

int
c2_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt)
{
    int i;
    char name[32];

    for (i = 0; i < c2_var_count; i++) {
        snprintf(name, sizeof(name), "2nd/string%d", i);
        cb(name, val_string[i]);
    }
    return 0;
}

struct conf_handler c3_test_handler = {
    .ch_name = "3",
    .ch_get = c3_handle_get,
    .ch_set = c3_handle_set,
    .ch_commit = NULL,
    .ch_export = c3_handle_export
};

char *
c3_handle_get(int argc, char **argv, char *val, int val_len_max)
{
    if (argc == 1 && !strcmp(argv[0], "v")) {
        return conf_str_from_value(CONF_INT32, &val32, val, val_len_max);
    }
    return NULL;
}

int
c3_handle_set(int argc, char **argv, char *val)
{
    uint32_t newval;
    int rc;

    if (argc == 1 && !strcmp(argv[0], "v")) {
        rc = CONF_VALUE_SET(val, CONF_INT32, newval);
        TEST_ASSERT(rc == 0);
        val32 = newval;
        return 0;
    }
    return OS_ENOENT;
}

int
c3_handle_export(void (*cb)(char *name, char *value),
  enum conf_export_tgt tgt)
{
    char value[32];

    conf_str_from_value(CONF_INT32, &val32, value, sizeof(value));
    cb("3/v", value);

    return 0;
}

void
ctest_clear_call_state(void)
{
    test_get_called = 0;
    test_set_called = 0;
    test_commit_called = 0;
}

int
ctest_get_call_state(void)
{
    return test_get_called + test_set_called + test_commit_called;
}

void config_wipe_srcs(void)
{
    SLIST_INIT(&conf_load_srcs);
    conf_save_dst = NULL;
}

void config_wipe_fcb2(struct flash_sector_range *fsr, int cnt)
{
    int rc;
    int i;

    for (i = 0; i < cnt; i++) {
        rc = flash_area_erase(&fsr[i].fsr_flash_area, 0,
                              fsr[i].fsr_sector_size * fsr[i].fsr_sector_count);
        TEST_ASSERT(rc == 0);
    }
}

struct flash_sector_range fcb_range[] = {
    [0] = {
        .fsr_flash_area = {
            .fa_off = 0x00000000,
            .fa_size = 64 * 1024
        },
        .fsr_range_start = 0,
        .fsr_first_sector = 0,
        .fsr_sector_size = 16 * 1024,
        .fsr_sector_count = 4,
        .fsr_align = 1,
    }
};

void
config_test_fill_area(
          char test_value[CONF_TEST_FCB_VAL_STR_CNT][CONF_MAX_VAL_LEN],
          int iteration)
{
      int i, j;

      for (j = 0; j < CONF_TEST_FCB_VAL_STR_CNT; j++) {
          for (i = 0; i < CONF_MAX_VAL_LEN; i++) {
              test_value[j][i] = ((j * 2) + i + iteration) % 10 + '0';
          }
          test_value[j][sizeof(test_value[j]) - 1] = '\0';
      }
}

static void
conf_test_fcb_pre_test(void *arg)
{
    int rc;

    rc = conf_register(&config_test_handler);
    TEST_ASSERT_FATAL(rc == 0);
}

static void
conf_test_fcb_pre_test2(void *arg)
{
    int rc;

    rc = conf_register(&config_test_handler);
    TEST_ASSERT_FATAL(rc == 0);

    rc = conf_register(&c2_test_handler);
    TEST_ASSERT_FATAL(rc == 0);
}

static void
conf_test_fcb_pre_test3(void *arg)
{
    int rc;

    rc = conf_register(&config_test_handler);
    TEST_ASSERT_FATAL(rc == 0);

    rc = conf_register(&c2_test_handler);
    TEST_ASSERT_FATAL(rc == 0);

    rc = conf_register(&c3_test_handler);
    TEST_ASSERT_FATAL(rc == 0);
}

TEST_SUITE(config_test_c0)
{
    config_empty_lookups();
}

TEST_SUITE(config_test_c1)
{
    tu_config.pre_test_cb = conf_test_fcb_pre_test;

    config_test_getset_unknown();
    config_test_getset_int();
    config_test_getset_bytes();
    config_test_getset_int64();

    config_test_commit();

    config_test_save_1_fcb();
}

TEST_SUITE(config_test_c2)
{
    tu_config.pre_test_cb = conf_test_fcb_pre_test2;

    config_test_empty_fcb();

    config_test_save_2_fcb();

    config_test_save_one_fcb();
    config_test_get_stored_fcb();
}

TEST_SUITE(config_test_c3)
{
    tu_config.pre_test_cb = conf_test_fcb_pre_test3;

    config_test_save_3_fcb();

    config_test_compress_reset();
    config_test_custom_compress();
}

int
main(int argc, char **argv)
{
    config_test_c0();
    config_test_c1();
    config_test_c2();
    config_test_c3();

    return tu_any_failed;
}
