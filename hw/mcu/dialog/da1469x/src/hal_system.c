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
#include "syscfg/syscfg.h"
#include "mcu/da1469x_clock.h"
#include "mcu/da1469x_lpclk.h"
#include "mcu/da1469x_pd.h"
#include "mcu/da1469x_pdc.h"
#include "mcu/da1469x_trimv.h"
#include "hal/hal_system.h"
#include "os/os_cputime.h"

#if !MYNEWT_VAL(BOOT_LOADER)
static enum hal_reset_reason g_hal_reset_reason;
#endif

void
hal_system_init(void)
{
    /*
     * RESET_STAT_REG has to be cleared to allow HW set bits during next reset
     * so we should read it now and keep result for application to check at any
     * time. This does not happen for bootloader since reading reset reason in
     * bootloader would prevent application from reading it.
     */

#if !MYNEWT_VAL(BOOT_LOADER)
    uint32_t reg;

    reg = CRG_TOP->RESET_STAT_REG;
    CRG_TOP->RESET_STAT_REG = 0;

    if (reg & CRG_TOP_RESET_STAT_REG_PORESET_STAT_Msk) {
        g_hal_reset_reason = HAL_RESET_POR;
    } else if (reg & CRG_TOP_RESET_STAT_REG_WDOGRESET_STAT_Msk) {
        g_hal_reset_reason = HAL_RESET_WATCHDOG;
    } else if (reg & CRG_TOP_RESET_STAT_REG_SWRESET_STAT_Msk) {
        g_hal_reset_reason = HAL_RESET_SOFT;
    } else if (reg & CRG_TOP_RESET_STAT_REG_HWRESET_STAT_Msk) {
        g_hal_reset_reason = HAL_RESET_PIN;
    } else {
        g_hal_reset_reason = 0;
    }
#endif

    da1469x_trimv_init_from_otp();
}

void
hal_system_reset(void)
{

#if MYNEWT_VAL(HAL_SYSTEM_RESET_CB)
    hal_system_reset_cb();
#endif

    while (1) {
        HAL_DEBUG_BREAK();
        NVIC_SystemReset();
    }
}

int
hal_debugger_connected(void)
{
    return CRG_TOP->SYS_STAT_REG & CRG_TOP_SYS_STAT_REG_DBG_IS_ACTIVE_Msk;
}

void
hal_system_clock_start(void)
{
    /* Reset clock dividers to 0 */
    CRG_TOP->CLK_AMBA_REG &= ~(CRG_TOP_CLK_AMBA_REG_HCLK_DIV_Msk | CRG_TOP_CLK_AMBA_REG_PCLK_DIV_Msk);

    /* Make sure PD_TIM is up since this is where XTAL32M state machine runs */
    da1469x_pd_acquire(MCU_PD_DOMAIN_TIM);

    /* Switch to XTAL32M and disable RC32M */
    da1469x_clock_sys_xtal32m_init();
    da1469x_clock_sys_xtal32m_enable();
    da1469x_clock_sys_xtal32m_switch_safe();
    da1469x_clock_sys_rc32m_disable();

#if MYNEWT_VAL_CHOICE(MCU_LPCLK_SOURCE, RCX)
    /* Switch to RCX and calibrate it */
    da1469x_clock_lp_rcx_enable();
    da1469x_clock_lp_rcx_switch();
    da1469x_clock_lp_rcx_calibrate();
    da1469x_lpclk_enabled();
#else
    /*
     * We cannot switch lp_clk to XTAL32K here since it needs some time to
     * settle, so we just disable RCX (we don't need it) and then we'll handle
     * switch to XTAL32K from sysinit since we need os_cputime for this.
     */
    da1469x_clock_lp_rcx_disable();
#endif
}

enum hal_reset_reason
hal_reset_cause(void)
{
#if MYNEWT_VAL(BOOT_LOADER)
    return 0;
#else
    return g_hal_reset_reason;
#endif
}
