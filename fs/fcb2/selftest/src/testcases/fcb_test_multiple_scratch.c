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
#include "fcb_test.h"

TEST_CASE_SELF(fcb_test_multiple_scratch)
{
    struct fcb2 *fcb;
    int rc;
    struct fcb2_entry loc;
    uint8_t test_data[128];
    int elem_cnts[4];
    int idx;
    int cnts[4];
    struct append_arg aa_arg = {
        .elem_cnts = cnts
    };

    fcb_tc_pretest(4);

    fcb = &test_fcb;
    fcb->f_scratch_cnt = 1;

    /*
     * Now fill up everything. We should be able to get 3 of the sectors
     * full.
     */
    memset(elem_cnts, 0, sizeof(elem_cnts));
    while (1) {
        rc = fcb2_append(fcb, sizeof(test_data), &loc);
        if (rc == FCB2_ERR_NOSPACE) {
            break;
        }
        idx = loc.fe_sector;
        elem_cnts[idx]++;

        rc = fcb2_write(&loc, 0, test_data, sizeof(test_data));
        TEST_ASSERT(rc == 0);

        rc = fcb2_append_finish(&loc);
        TEST_ASSERT(rc == 0);
    }

    TEST_ASSERT(elem_cnts[0] > 0);
    TEST_ASSERT(elem_cnts[0] == elem_cnts[1] && elem_cnts[0] == elem_cnts[2]);
    TEST_ASSERT(elem_cnts[3] == 0);

    /*
     * Ask to use scratch block, then fill it up.
     */
    rc = fcb2_append_to_scratch(fcb);
    TEST_ASSERT(rc == 0);

    while (1) {
        rc = fcb2_append(fcb, sizeof(test_data), &loc);
        if (rc == FCB2_ERR_NOSPACE) {
            break;
        }
        idx = loc.fe_sector;
        elem_cnts[idx]++;

        rc = fcb2_write(&loc, 0, test_data, sizeof(test_data));
        TEST_ASSERT(rc == 0);

        rc = fcb2_append_finish(&loc);
        TEST_ASSERT(rc == 0);
    }
    TEST_ASSERT(elem_cnts[3] == elem_cnts[0]);

    /*
     * Rotate
     */
    rc = fcb2_rotate(fcb);
    TEST_ASSERT(rc == 0);

    memset(&cnts, 0, sizeof(cnts));
    rc = fcb2_walk(fcb, FCB2_SECTOR_OLDEST, fcb_test_cnt_elems_cb, &aa_arg);
    TEST_ASSERT(rc == 0);

    TEST_ASSERT(cnts[0] == 0);
    TEST_ASSERT(cnts[1] > 0);
    TEST_ASSERT(cnts[1] == cnts[2] && cnts[1] == cnts[3]);

    rc = fcb2_append_to_scratch(fcb);
    TEST_ASSERT(rc == 0);
    rc = fcb2_append_to_scratch(fcb);
    TEST_ASSERT(rc != 0);
}
