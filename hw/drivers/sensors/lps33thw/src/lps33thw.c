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

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include "os/mynewt.h"
#include "hal/hal_gpio.h"
#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
#include "bus/drivers/i2c_common.h"
#include "bus/drivers/spi_common.h"
#else
#include "hal/hal_i2c.h"
#include "hal/hal_spi.h"
#include "i2cn/i2cn.h"
#endif
#include "sensor/sensor.h"
#include "sensor/pressure.h"
#include "sensor/temperature.h"
#include "lps33thw/lps33thw.h"
#include "lps33thw_priv.h"
#include "modlog/modlog.h"
#include "stats/stats.h"
#include <syscfg/syscfg.h>

#if !MYNEWT_VAL(BUS_DRIVER_PRESENT)
static struct hal_spi_settings spi_lps33thw_settings = {
    .data_order = HAL_SPI_MSB_FIRST,
    .data_mode  = HAL_SPI_MODE3,
    .baudrate   = 4000,
    .word_size  = HAL_SPI_WORD_SIZE_8BIT,
};
#endif

/* Define the stats section and records */
STATS_SECT_START(lps33thw_stat_section)
    STATS_SECT_ENTRY(read_errors)
    STATS_SECT_ENTRY(write_errors)
STATS_SECT_END

/* Define stat names for querying */
STATS_NAME_START(lps33thw_stat_section)
    STATS_NAME(lps33thw_stat_section, read_errors)
    STATS_NAME(lps33thw_stat_section, write_errors)
STATS_NAME_END(lps33thw_stat_section)

/* Global variable used to hold stats data */
STATS_SECT_DECL(lps33thw_stat_section) g_lps33thwstats;

#define LPS33THW_PRESS_OUT_DIV (40.96f)
#define LPS33THW_TEMP_OUT_DIV (100.0f)
#define LPS33THW_PRESS_THRESH_DIV (16)

/* Exports for the sensor API */
static int lps33thw_sensor_read(struct sensor *, sensor_type_t,
        sensor_data_func_t, void *, uint32_t);
static int lps33thw_sensor_get_config(struct sensor *, sensor_type_t,
        struct sensor_cfg *);
static int lps33thw_sensor_set_config(struct sensor *, void *);
static int lps33thw_sensor_set_trigger_thresh(struct sensor *sensor,
        sensor_type_t sensor_type, struct sensor_type_traits *stt);
static int lps33thw_sensor_handle_interrupt(struct sensor *sensor);
static int lps33thw_sensor_clear_low_thresh(struct sensor *sensor,
        sensor_type_t type);
static int lps33thw_sensor_clear_high_thresh(struct sensor *sensor,
        sensor_type_t type);
static void lps33thw_read_interrupt_handler(void *arg);

#if MYNEWT_VAL(LPS33THW_ONE_SHOT_MODE)
#define LPS33THW_ONE_SHOT_TICKS	2
static void lps33thw_one_shot_read_cb(struct os_event *ev);
#endif

static const struct sensor_driver g_lps33thw_sensor_driver = {
    .sd_read                      = lps33thw_sensor_read,
    .sd_get_config                = lps33thw_sensor_get_config,
    .sd_set_config                = lps33thw_sensor_set_config,
    .sd_set_trigger_thresh        = lps33thw_sensor_set_trigger_thresh,
    .sd_handle_interrupt          = lps33thw_sensor_handle_interrupt,
    .sd_clear_low_trigger_thresh  = lps33thw_sensor_clear_low_thresh,
    .sd_clear_high_trigger_thresh = lps33thw_sensor_clear_high_thresh,
    .sd_reset                     = lps33thw_reset
};

/*
 * Sensor read after ONE_SHOT conversion
 */
#if MYNEWT_VAL(LPS33THW_ONE_SHOT_MODE)
static void lps33thw_one_shot_read_cb(struct os_event *ev)
{
    int rc;
    struct lps33thw *lps33thw = (struct lps33thw *)ev->ev_arg;
    struct sensor *sensor = &lps33thw->sensor;
    struct sensor_itf *itf = SENSOR_GET_ITF(sensor);

    if (lps33thw->type & SENSOR_TYPE_PRESSURE) {
        if (lps33thw->cfg.int_cfg.data_rdy) {
            /* Stream read */
            rc = lps33thw_enable_interrupt(sensor,
                    lps33thw_read_interrupt_handler, sensor);
        } else {
            /* Read once */
            struct sensor_press_data spd;
            float press;
            rc = lps33thw_get_pressure(itf, &press);
            if (!rc) {
                spd.spd_press = press;
                spd.spd_press_is_valid = 1;
                rc = lps33thw->data_func(sensor, &lps33thw->pdd.user_ctx, &spd, SENSOR_TYPE_PRESSURE);
            }
        }
    }
    if (lps33thw->type & SENSOR_TYPE_TEMPERATURE) {
        struct sensor_temp_data std;
        float temp;
        rc = lps33thw_get_temperature(itf, &temp);
        if (!rc) {
            std.std_temp = temp;
            std.std_temp_is_valid = 1;
            rc = lps33thw->data_func(sensor, &lps33thw->pdd.user_ctx, &std,
                    SENSOR_TYPE_TEMPERATURE);
        }
    }
}
#endif

/*
 * Converts pressure value in pascals to a value found in the pressure
 * threshold register of the device.
 *
 * @param Pressure value in pascals.
 *
 * @return Pressure value to write to the threshold registers.
 */
static uint16_t
lps33thw_pa_to_threshold_reg(float pa)
{
    /* Threshold is unsigned. */
    if (pa < 0) {
        return 0;
    } else if (pa == INFINITY) {
        return 0xffff;
    }
    return pa * LPS33THW_PRESS_THRESH_DIV;
}

/*
 * Converts pressure value in pascals to a value found in the pressure
 * reference register of the device.
 *
 * @param Pressure value in pascals.
 *
 * @return Pressure value to write to the reference registers.
 */
static int32_t
lps33thw_pa_to_reg(float pa)
{
    if (pa == INFINITY) {
        return 0x007fffff;
    }
    return (int32_t)(pa * LPS33THW_PRESS_OUT_DIV);
}

/*
 * Converts pressure read from the device output registers to a value in
 * pascals.
 *
 * @param Pressure value read from the output registers.
 *
 * @return Pressure value in pascals.
 */
static float
lps33thw_reg_to_pa(int32_t reg)
{
    return reg / LPS33THW_PRESS_OUT_DIV;
}

/*
 * Converts temperature read from the device output registers to a value in
 * degrees C.
 *
 * @param Temperature value read from the output registers.
 *
 * @return Temperature value in degrees C.
 */
static float
lps33thw_reg_to_degc(int16_t reg)
{
    return reg / LPS33THW_TEMP_OUT_DIV;
}

#if !MYNEWT_VAL(BUS_DRIVER_PRESENT)
/**
 * Writes a single byte to the specified register using i2c
 * interface
 *
 * @param The sensor interface
 * @param The register address to write to
 * @param The value to write
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_i2c_set_reg(struct sensor_itf *itf, uint8_t reg, uint8_t value)
{
    int rc;
    uint8_t payload[2] = { reg, value };

    struct hal_i2c_master_data data_struct = {
        .address = itf->si_addr,
        .len = 2,
        .buffer = payload
    };

    rc = i2cn_master_write(itf->si_num, &data_struct, MYNEWT_VAL(LPS33THW_I2C_TIMEOUT_TICKS), 1,
                           MYNEWT_VAL(LPS33THW_I2C_RETRIES));

    if (rc) {
        LPS33THW_LOG_ERROR(
                    "Failed to write to 0x%02X:0x%02X with value 0x%02X\n",
                    itf->si_addr, reg, value);
        STATS_INC(g_lps33thwstats, read_errors);
    }

    return rc;
}

/**
 * Writes a single byte to the specified register using SPI
 * interface
 *
 * @param The sensor interface
 * @param The register address to write to
 * @param The value to write
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_spi_set_reg(struct sensor_itf *itf, uint8_t reg, uint8_t value)
{
    int rc;

    /* Select the device */
    hal_gpio_write(itf->si_cs_pin, 0);

    /* Send the register address w/write command */
    rc = hal_spi_tx_val(itf->si_num, reg & ~LPS33THW_SPI_READ_CMD_BIT);
    if (rc == 0xFFFF) {
        rc = SYS_EINVAL;
        LPS33THW_LOG_ERROR("SPI_%u register write failed addr:0x%02X\n",
                    itf->si_num, reg);
        STATS_INC(g_lps33thwstats, write_errors);
        goto err;
    }

    /* Write data */
    rc = hal_spi_tx_val(itf->si_num, value);
    if (rc == 0xFFFF) {
        rc = SYS_EINVAL;
        LPS33THW_LOG_ERROR("SPI_%u write failed addr:0x%02X\n",
                    itf->si_num, reg);
        STATS_INC(g_lps33thwstats, write_errors);
        goto err;
    }

    rc = 0;

err:
    /* De-select the device */
    hal_gpio_write(itf->si_cs_pin, 1);

    os_time_delay((OS_TICKS_PER_SEC * 30)/1000 + 1);

    return rc;
}
#endif

/**
 * Writes a single byte to the specified register using specified
 * interface
 *
 * @param The sensor interface
 * @param The register address to write to
 * @param The value to write
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_set_reg(struct sensor_itf *itf, uint8_t reg, uint8_t value)
{
    int rc;

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
    uint8_t data[2] = { reg, value };

    rc = bus_node_simple_write(itf->si_dev, data, 2);
#else
    rc = sensor_itf_lock(itf, MYNEWT_VAL(LPS33THW_ITF_LOCK_TMO));
    if (rc) {
        return rc;
    }

    if (itf->si_type == SENSOR_ITF_I2C) {
        rc = lps33thw_i2c_set_reg(itf, reg, value);
    } else {
        rc = lps33thw_spi_set_reg(itf, reg, value);
    }

    sensor_itf_unlock(itf);
#endif

    return rc;
}

#if !MYNEWT_VAL(BUS_DRIVER_PRESENT)
/**
 *
 * Read bytes from the specified register using SPI interface
 *
 * @param The sensor interface
 * @param The register address to read from
 * @param The number of bytes to read
 * @param Pointer to where the register value should be written
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_spi_get_regs(struct sensor_itf *itf, uint8_t reg, uint8_t size,
    uint8_t *buffer)
{
    int i;
    uint16_t retval;
    int rc;
    rc = 0;

    /* Select the device */
    hal_gpio_write(itf->si_cs_pin, 0);

    /* Send the address */
    retval = hal_spi_tx_val(itf->si_num, reg | LPS33THW_SPI_READ_CMD_BIT);
    if (retval == 0xFFFF) {
        rc = SYS_EINVAL;
        LPS33THW_LOG_ERROR("SPI_%u register write failed addr:0x%02X\n",
                    itf->si_num, reg);
        STATS_INC(g_lps33thwstats, read_errors);
        goto err;
    }

    for (i = 0; i < size; i++) {
        /* Read data */
        retval = hal_spi_tx_val(itf->si_num, 0);
        if (retval == 0xFFFF) {
            rc = SYS_EINVAL;
            LPS33THW_LOG_ERROR("SPI_%u read failed addr:0x%02X\n",
                        itf->si_num, reg);
            STATS_INC(g_lps33thwstats, read_errors);
            goto err;
        }
        buffer[i] = retval;
    }

    rc = 0;

err:
    /* De-select the device */
    hal_gpio_write(itf->si_cs_pin, 1);

    return rc;
}

/**
 * Read bytes from the specified register using i2c interface
 *
 * @param The sensor interface
 * @param The register address to read from
 * @param The number of bytes to read
 * @param Pointer to where the register value should be written
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_i2c_get_regs(struct sensor_itf *itf, uint8_t reg, uint8_t size,
    uint8_t *buffer)
{
    int rc;

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
    struct os_dev *odev = SENSOR_ITF_GET_DEVICE(itf);

    rc = bus_node_simple_write_read_transact(odev, &reg, 1, buffer, size);
#else
    struct hal_i2c_master_data wdata = {
        .address = itf->si_addr,
        .len = 1,
        .buffer = &reg
    };
    struct hal_i2c_master_data rdata = {
        .address = itf->si_addr,
        .len = size,
        .buffer = buffer,
    };

    rc = i2cn_master_write_read_transact(itf->si_num, &wdata, &rdata,
                                         MYNEWT_VAL(LPS33THW_I2C_TIMEOUT_TICKS) * (size + 1),
                                         1, MYNEWT_VAL(LPS33THW_I2C_RETRIES));
    if (rc) {
        LPS33THW_LOG_ERROR("I2C access failed at address 0x%02X\n",
                     itf->si_addr);
        STATS_INC(g_lps33thwstats, read_errors);
        return rc;
    }
#endif

    return rc;
}
#endif

/**
 * Read bytes from the specified register using specified interface
 *
 * @param The sensor interface
 * @param The register address to read from
 * @param The number of bytes to read
 * @param Pointer to where the register value should be written
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_get_regs(struct sensor_itf *itf, uint8_t reg, uint8_t size,
		  uint8_t *buffer)
{
    int rc;

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
    struct lps33thw *dev = (struct lps33thw *)itf->si_dev;

    if (dev->node_is_spi) {
        reg |= LPS33THW_SPI_READ_CMD_BIT;
    }

    rc = bus_node_simple_write_read_transact(itf->si_dev, &reg, 1, buffer, size);
#else
    rc = sensor_itf_lock(itf, MYNEWT_VAL(LPS33THW_ITF_LOCK_TMO));
    if (rc) {
        return rc;
    }

    if (itf->si_type == SENSOR_ITF_I2C) {
        rc = lps33thw_i2c_get_regs(itf, reg, size, buffer);
    } else {
        rc = lps33thw_spi_get_regs(itf, reg, size, buffer);
    }

    sensor_itf_unlock(itf);
#endif

    return rc;
}

static int
lps33thw_apply_value(struct lps33thw_register_value addr, uint8_t value,
    uint8_t *reg)
{
    value <<= addr.pos;

    if ((value & (~addr.mask)) != 0) {
        return -1;
    }

    *reg &= ~addr.mask;
    *reg |= value;

    return 0;
}

int
lps33thw_set_value(struct sensor_itf *itf, struct lps33thw_register_value addr,
    uint8_t value)
{
    int rc;
    uint8_t reg;

    rc = lps33thw_get_regs(itf, addr.reg, 1, &reg);
    if (rc != 0) {
        return rc;
    }

    rc = lps33thw_apply_value(addr, value, &reg);
    if (rc != 0) {
        return rc;
    }

    return lps33thw_set_reg(itf, addr.reg, reg);
}

int
lps33thw_get_value(struct sensor_itf *itf, struct lps33thw_register_value addr,
    uint8_t *value)
{
    int rc;
    uint8_t reg;

    rc = lps33thw_get_regs(itf, addr.reg, 1, &reg);

    *value = (reg & addr.mask) >> addr.pos;

    return rc;
}

int
lps33thw_set_data_rate(struct sensor_itf *itf,
    enum lps33thw_output_data_rates rate)
{
    return lps33thw_set_value(itf, LPS33THW_CTRL_REG1_ODR, rate);
}

int
lps33thw_set_lpf(struct sensor_itf *itf, enum lps33thw_low_pass_config lpf)
{
    return lps33thw_set_value(itf, LPS33THW_CTRL_REG1_LPFP_CFG, lpf);
}

int
lps33thw_reset(struct sensor *sensor)
{
    struct sensor_itf *itf;

    itf = SENSOR_GET_ITF(sensor);

    return lps33thw_set_reg(itf, LPS33THW_CTRL_REG2, 0x04);
}

int
lps33thw_get_pressure_regs(struct sensor_itf *itf, uint8_t reg, float *pressure)
{
    int rc;
    uint8_t payload[3];
    int32_t int_press;

    rc = lps33thw_get_regs(itf, reg, 3, payload);
    if (rc) {
        return rc;
    }

    int_press = ((int8_t)payload[2] << 16) | (payload[1] << 8) | payload[0];

    *pressure = lps33thw_reg_to_pa(int_press);

    return 0;
}

int
lps33thw_get_pressure(struct sensor_itf *itf, float *pressure) {
    return lps33thw_get_pressure_regs(itf, LPS33THW_PRESS_OUT, pressure);
}

int
lps33thw_get_temperature(struct sensor_itf *itf, float *temperature)
{
    int rc;
    uint8_t payload[2];
    uint16_t int_temp;

    rc = lps33thw_get_regs(itf, LPS33THW_TEMP_OUT, 2, payload);
    if (rc) {
        return rc;
    }

    int_temp = (((uint32_t)payload[1] << 8) | payload[0]);

    *temperature = lps33thw_reg_to_degc(int_temp);

    return 0;
}

int
lps33thw_set_reference(struct sensor_itf *itf, float reference)
{
    int rc;
    int32_t int_reference;

    int_reference = lps33thw_pa_to_reg(reference);

    rc = lps33thw_set_reg(itf, LPS33THW_REF_P, int_reference & 0xff);
    if (rc) {
        return rc;
    }

    return lps33thw_set_reg(itf, LPS33THW_REF_P + 1, (int_reference >> 8) & 0xff);
}

int
lps33thw_set_threshold(struct sensor_itf *itf, float threshold)
{
    int rc;
    int16_t int_threshold;

    int_threshold = lps33thw_pa_to_threshold_reg(threshold);

    rc = lps33thw_set_reg(itf, LPS33THW_THS_P, int_threshold & 0xff);
    if (rc) {
        return rc;
    }

    return lps33thw_set_reg(itf, LPS33THW_THS_P + 1, (int_threshold >> 8) & 0xff);
}

int
lps33thw_set_rpds(struct sensor_itf *itf, uint16_t rpds)
{
    int rc;

    rc = lps33thw_set_reg(itf, LPS33THW_RPDS, rpds & 0xff);
    if (rc) {
        return rc;
    }

    return lps33thw_set_reg(itf, LPS33THW_RPDS + 1, (rpds >> 8) & 0xff);
}

int
lps33thw_enable_interrupt(struct sensor *sensor, hal_gpio_irq_handler_t handler,
            void *arg)
{
    int rc;
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;
    hal_gpio_irq_trig_t trig;
    hal_gpio_pull_t pull;
    struct lps33thw_int_cfg *int_cfg;
    float press;
    uint8_t int_source;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);
    int_cfg = &lps33thw->cfg.int_cfg;
    trig = (int_cfg->active_low) ? HAL_GPIO_TRIG_FALLING : HAL_GPIO_TRIG_RISING;
    pull = (int_cfg->open_drain) ? HAL_GPIO_PULL_UP : HAL_GPIO_PULL_NONE;

    rc = hal_gpio_irq_init(int_cfg->pin, handler, arg, trig, pull);
    if (rc) {
        return rc;
    }

    hal_gpio_irq_enable(int_cfg->pin);

    /* Read pressure and interrupt sources in order to reset the interrupt */
    rc = lps33thw_get_pressure_regs(itf, LPS33THW_PRESS_OUT, &press);
    if (rc) {
        return rc;
    }
    (void)press;
    lps33thw->pdd.interrupt = &lps33thw->interrupt;

    rc = lps33thw_get_regs(itf, LPS33THW_INT_SOURCE, 1, &int_source);
    if (rc) {
        return rc;
    }
    (void)int_source;

    return 0;
}

void
lps33thw_disable_interrupt(struct sensor *sensor)
{
    struct lps33thw *lps33thw;
    struct lps33thw_int_cfg *int_cfg;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    int_cfg = &lps33thw->cfg.int_cfg;
    lps33thw->pdd.interrupt = NULL;

    hal_gpio_irq_release(int_cfg->pin);
}

/**
 * Handles and interrupt
 *
 * @param Pointer to sensor structure
 *
 * @return 0 on success, non-zero on failure
 */
static int
lps33thw_sensor_handle_interrupt(struct sensor *sensor)
{
    LPS33THW_LOG_ERROR("Unhandled interrupt\n");
    return 0;
}

/**
 * Clears the low threshold interrupt
 *
 * @param Pointer to sensor structure
 * @param Sensor type
 *
 * @return 0 on success, non-zero on failure
 */
static int
lps33thw_sensor_clear_low_thresh(struct sensor *sensor, sensor_type_t type)
{
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;
    struct lps33thw_int_cfg *int_cfg;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);
    int_cfg = &lps33thw->cfg.int_cfg;

    if (type != SENSOR_TYPE_PRESSURE) {
        return SYS_EINVAL;
    }

    int_cfg->pressure_low = 0;

    return lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PLE, 0);
}

/**
 * Clears the high threshold interrupt
 *
 * @param Pointer to sensor structure
 * @param Sensor type
 *
 * @return 0 on success, non-zero on failure
 */
static int
lps33thw_sensor_clear_high_thresh(struct sensor *sensor, sensor_type_t type)
{
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;
    struct lps33thw_int_cfg *int_cfg;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);
    int_cfg = &lps33thw->cfg.int_cfg;

    if (type != SENSOR_TYPE_PRESSURE) {
        return SYS_EINVAL;
    }

    int_cfg->pressure_high = 0;

    return lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PHE, 0);
}

static void
lps33thw_threshold_interrupt_handler(void * arg)
{
    struct sensor_type_traits *stt = arg;
    sensor_mgr_put_read_evt(stt);
}

int
lps33thw_config_interrupt(struct sensor *sensor, struct lps33thw_int_cfg cfg)
{
    int rc;
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);

    lps33thw->cfg.int_cfg = cfg;

    if (cfg.data_rdy || cfg.fifo_wtm_rdy) {
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PLE, 0);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PHE, 0);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_DIFF_EN, 0);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG3_INT_S, 0);
        if (rc) {
            return rc;
        }
    } else if (cfg.pressure_low || cfg.pressure_high) {
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PLE,
            cfg.pressure_low);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_PHE,
            cfg.pressure_high);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_DIFF_EN, 1);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG3_INT_S,
				cfg.pressure_high | (cfg.pressure_low << 1));
        if (rc) {
            return rc;
        }
    } else {
        rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_DIFF_EN, 0);
        if (rc) {
            return rc;
        }
    }
    rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG3_DRDY, cfg.data_rdy);
    if (rc) {
        return rc;
    }
    rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG3_F_FTH, cfg.fifo_wtm_rdy);
    if (rc) {
        return rc;
    }
    rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG2_INT_H_L, cfg.active_low);
    if (rc) {
        return rc;
    }
    rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG2_PP_OD, cfg.open_drain);
    if (rc) {
        return rc;
    }
    rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_LIR, cfg.latched);
    if (rc) {
        return rc;
    }

    return rc;
}

/**
 * Sets up trigger thresholds and enables interrupts
 *
 * @param Pointer to sensor structure
 * @param type of sensor
 * @param threshold settings to configure
 *
 * @return 0 on success, non-zero on failure
 */
static int
lps33thw_sensor_set_trigger_thresh(struct sensor *sensor,
                                  sensor_type_t sensor_type,
                                  struct sensor_type_traits *stt)
{
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;
    int rc;
    struct sensor_press_data *low_thresh;
    struct sensor_press_data *high_thresh;
    struct lps33thw_int_cfg int_cfg;
    float reference;
    float threshold;

    if (sensor_type != SENSOR_TYPE_PRESSURE) {
        return SYS_EINVAL;
    }

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);

    low_thresh  = stt->stt_low_thresh.spd;
    high_thresh = stt->stt_high_thresh.spd;
    int_cfg = lps33thw->cfg.int_cfg;

    /* turn off existing dready interrupt */
    int_cfg.data_rdy = 0;
    int_cfg.pressure_low = low_thresh->spd_press_is_valid;
    int_cfg.pressure_high = high_thresh->spd_press_is_valid;

    threshold = 0;
    reference = 0;

    /*
     * Device only has one threshold which can be set to trigger on positive or
     * negative thresholds, set it to the lower threshold.
     */

    if (int_cfg.pressure_low) {
        if (int_cfg.pressure_high) {
            threshold = (high_thresh->spd_press - low_thresh->spd_press) / 2;
            reference = low_thresh->spd_press + threshold;
        } else {
            reference = low_thresh->spd_press;
        }
    } else if (int_cfg.pressure_high) {
        reference = high_thresh->spd_press;
    }

    rc = lps33thw_set_reference(itf, reference);
    if (rc) {
        return rc;
    }

    rc = lps33thw_set_threshold(itf, threshold);
    if (rc) {
        return rc;
    }

    rc = lps33thw_config_interrupt(sensor, int_cfg);
    if (rc) {
        return rc;
    }

    rc = lps33thw_enable_interrupt(sensor, lps33thw_threshold_interrupt_handler,
        stt);
    if (rc) {
        return rc;
    }

    return 0;
}

int
lps33thw_init(struct os_dev *dev, void *arg)
{
    struct lps33thw *lps;
    struct sensor *sensor;
    int rc;
    os_error_t error;

    if (!arg || !dev) {
        return SYS_ENODEV;
    }

    lps = (struct lps33thw *)dev;
#if MYNEWT_VAL(LPS33THW_ONE_SHOT_MODE)
    os_callout_init(&lps->lps33thw_one_shot_read, sensor_mgr_evq_get(),
		    lps33thw_one_shot_read_cb, dev);
#endif

    sensor = &lps->sensor;
    lps->cfg.mask = SENSOR_TYPE_ALL;

    /* Initialise the stats entry */
    rc = stats_init(STATS_HDR(g_lps33thwstats),
        STATS_SIZE_INIT_PARMS(g_lps33thwstats, STATS_SIZE_32),
        STATS_NAME_INIT_PARMS(lps33thw_stat_section));
    SYSINIT_PANIC_ASSERT(rc == 0);

    /* Register the entry with the stats registry */
    rc = stats_register(dev->od_name, STATS_HDR(g_lps33thwstats));
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = sensor_init(sensor, dev);
    if (rc) {
        return rc;
    }

    /* Add the pressure and temperature driver */
    rc = sensor_set_driver(sensor, SENSOR_TYPE_PRESSURE |
        SENSOR_TYPE_TEMPERATURE,
        (struct sensor_driver *) &g_lps33thw_sensor_driver);
    if (rc) {
        return rc;
    }

    rc = sensor_set_interface(sensor, arg);
    if (rc) {
        return rc;
    }

    rc = sensor_mgr_register(sensor);
    if (rc) {
        return rc;
    }

    /* Init semaphore for task to wait on when irq asleep */
    error = os_sem_init(&(lps->interrupt.wait), 0);
    assert(error == OS_OK);

#if !MYNEWT_VAL(BUS_DRIVER_PRESENT)
    if (sensor->s_itf.si_type == SENSOR_ITF_SPI) {
        rc = hal_spi_config(sensor->s_itf.si_num, &spi_lps33thw_settings);
        if (rc == EINVAL) {
            /* If spi is already enabled, for nrf52, it returns -1, We should not
             * fail if the spi is already enabled
             */
            return rc;
        }

        rc = hal_spi_enable(sensor->s_itf.si_num);
        if (rc) {
            return rc;
        }

        rc = hal_gpio_init_out(sensor->s_itf.si_cs_pin, 1);
        if (rc) {
            return rc;
        }
    }
#endif

    return rc;
}

int
lps33thw_config(struct lps33thw *lps, struct lps33thw_cfg *cfg)
{
    int rc;
    struct sensor_itf *itf;
    uint8_t val;

    itf = SENSOR_GET_ITF(&(lps->sensor));
    rc = lps33thw_get_regs(itf, LPS33THW_WHO_AM_I, 1, &val);
    if (rc) {
        return rc;
    }
    if (val != LPS33THW_WHO_AM_I_VAL) {
        return SYS_EINVAL;
    }

    rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_AUTORIFP,
			    cfg->autorifp);
    if (rc) {
        return rc;
    }
    lps->cfg.autorifp = cfg->autorifp;

    rc = lps33thw_set_value(itf, LPS33THW_INTERRUPT_CFG_AUTOZERO,
			    cfg->autozero);
    if (rc) {
        return rc;
    }
    lps->cfg.autozero = cfg->autozero;

    rc = lps33thw_set_data_rate(itf, cfg->data_rate);
    if (rc) {
        return rc;
    }
    lps->cfg.data_rate = cfg->data_rate;

    rc = lps33thw_set_lpf(itf, cfg->lpf);
    if (rc) {
        return rc;
    }
    lps->cfg.lpf = cfg->lpf;

    rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG2_LOW_NOISE_EN,
			    cfg->low_noise_en);
    if (rc) {
        return rc;
    }
    lps->cfg.low_noise_en = cfg->low_noise_en;

    /* Configure FIFO watermark */
    rc = lps33thw_set_value(itf, LPS33THW_FIFO_WTM_THR, cfg->fifo_wtm);
    if (rc) {
        return rc;
    }
    lps->cfg.fifo_wtm = cfg->fifo_wtm;

    rc = lps33thw_config_interrupt(&(lps->sensor), cfg->int_cfg);
    if (rc) {
        return rc;
    }
    lps->cfg.int_cfg = cfg->int_cfg;

    rc = sensor_set_type_mask(&(lps->sensor), cfg->mask);
    if (rc) {
        return rc;
    }

    lps->cfg.mask = cfg->mask;
    lps->cfg.read_mode = cfg->read_mode;

    return 0;
}

static void
lps33thw_read_interrupt_handler(void *arg)
{
    int rc;
    struct sensor *sensor;
    struct lps33thw *lps33thw;
    struct sensor_itf *itf;
    struct sensor_press_data spd;
    float press;

    sensor = (struct sensor *)arg;
    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    itf = SENSOR_GET_ITF(sensor);

    rc = lps33thw_get_pressure(itf, &press);
    if (rc) {
        LPS33THW_LOG_ERROR("Get pressure failed\n");
        spd.spd_press_is_valid = 0;
    } else {
        spd.spd_press = press;
        spd.spd_press_is_valid = 1;
        lps33thw->pdd.user_ctx.user_func(sensor, lps33thw->pdd.user_ctx.user_arg,
            &spd, SENSOR_TYPE_PRESSURE);
    }
}

static int
lps33thw_sensor_read_poll(struct sensor *sensor, sensor_type_t type,
        sensor_data_func_t data_func, void *data_arg)
{
    int rc = SYS_EINVAL;
    struct sensor_itf *itf = SENSOR_GET_ITF(sensor);
    uint8_t rate;
    struct lps33thw *lps33thw  = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);

    rc = lps33thw_get_value(itf, LPS33THW_CTRL_REG1_ODR, &rate);
    if (rc) {
        return rc;
    }

#if MYNEWT_VAL(LPS33THW_ONE_SHOT_MODE)
    if (rate != LPS33THW_75HZ) {
        lps33thw->data_func = data_func;
        lps33thw->pdd.user_ctx = *(struct sensor_read_ctx *)data_arg;
        lps33thw->type = type;
        rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG1_ODR, LPS33THW_ONE_SHOT);
        if (rc) {
            return rc;
        }
        rc = lps33thw_set_value(itf, LPS33THW_CTRL_REG2_ONE_SHOT, 0x01);
        if (rc) {
            return rc;
        }
        os_callout_reset(&lps33thw->lps33thw_one_shot_read, LPS33THW_ONE_SHOT_TICKS);
        return rc;
    }
#endif

    if (type & SENSOR_TYPE_PRESSURE) {
        if (lps33thw->cfg.int_cfg.data_rdy) {
            /* Stream read */
            lps33thw->pdd.user_ctx.user_func = data_func;
            lps33thw->pdd.user_ctx.user_arg = data_arg;
            rc = lps33thw_enable_interrupt(sensor,
                    lps33thw_read_interrupt_handler, sensor);
            if (rc) {
                return rc;
            }
	} else {
            /* Read once */
            struct sensor_press_data spd;
            float press;
            rc = lps33thw_get_pressure(itf, &press);
            if (rc) {
                return rc;
            }
            spd.spd_press = press;
            spd.spd_press_is_valid = 1;

            rc = data_func(sensor, data_arg, &spd, SENSOR_TYPE_PRESSURE);
        }
    }
    if (type & SENSOR_TYPE_TEMPERATURE) {
        struct sensor_temp_data std;
        float temp;
        rc = lps33thw_get_temperature(itf, &temp);
        if (rc) {
            return rc;
        }
        std.std_temp = temp;
        std.std_temp_is_valid = 1;

        rc = data_func(sensor, data_arg, &std,
                SENSOR_TYPE_TEMPERATURE);
    }
    if (!(type & SENSOR_TYPE_TEMPERATURE) && !(type & SENSOR_TYPE_PRESSURE)) {
        return SYS_EINVAL;
    }

    return rc;
}

static int lps33thw_read_fifo(struct sensor_itf *itf,
			      struct sensor_temp_data *std,
			      struct sensor_press_data *spd)
{
    int rc;
    uint8_t fifo_data[5];
    int32_t int_press;
    int16_t int_temp;

    rc = lps33thw_get_regs(itf, LPS33THW_FIFO_SDATA_OUT_PRESS, 5, fifo_data);
    if (rc) {
	return rc;
    }

    int_press = ((int8_t)fifo_data[2] << 16) | (fifo_data[1] << 8) | fifo_data[0];
    spd->spd_press_is_valid = 1;
    spd->spd_press = lps33thw_reg_to_pa(int_press);

    int_temp = ((int8_t)fifo_data[4] << 8) | fifo_data[3];
    std->std_temp_is_valid = 1;
    std->std_temp = lps33thw_reg_to_degc(int_temp);

    return 0;
}

static int lps33thw_wait_interrupt(struct lps33thw_int *interrupt)
{
    os_error_t error;

    error = os_sem_pend(&interrupt->wait, LPS33THW_MAX_INT_WAIT);
    if (error == OS_TIMEOUT) {
	return error;
    }
    assert(error == OS_OK);

    return OS_OK;
}

/**
 * Wake tasks waiting on interrupt->wait lock
 *
 * This call resume task waiting on lps33thw_wake_interrupt lock
 *
 * @param the interrupt structure
 *
 * @return 0 on success, non-zero on failure
 */
static void lps33thw_wake_interrupt(struct lps33thw_int *interrupt)
{
    os_error_t error;

    /* Release semaphore to wait_interrupt routine */
    error = os_sem_release(&interrupt->wait);
    assert(error == OS_OK);
}

/**
 * Wake tasks waiting on interrupt->wait lock
 *
 * This call resume task waiting on lps33thw_wake_interrupt lock
 *
 * @param the interrupt structure
 *
 * @return 0 on success, non-zero on failure
 */
static void lps33thw_int_irq_handler(void *arg)
{
    struct sensor *sensor = arg;
    struct lps33thw *lps33thw;

    lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);

    if(lps33thw->pdd.interrupt) {
        lps33thw_wake_interrupt(lps33thw->pdd.interrupt);
    }
}

/**
 * Read data samples from FIFO
 *
 * FIFO store both SENSOR_TYPE_TEMPERATURE
 * and SENSOR_TYPE_PRESSURE sample data
 *
 * @param sensor The sensor object
 * @param type sensor type bitmask
 * @param data_func callback register data function
 * @param data_arg function arguments
 * @param time_ms
 *
 * @return 0 on success, non-zero error on failure.
 */
int lps33thw_stream_read(struct sensor *sensor, sensor_type_t sensor_type,
                        sensor_data_func_t read_func, void *data_arg,
                        uint32_t time_ms)
{
    struct lps33thw *lps33thw;
    struct lps33thw_private_driver_data *pdd;
    struct sensor_itf *itf;
    uint8_t fifo_samples;
    os_time_t time_ticks;
    os_time_t stop_ticks = 0;
    int rc;
    struct sensor_temp_data std;
    struct sensor_press_data spd;

    /* Temperature/Pressure only */
    if (!(sensor_type & SENSOR_TYPE_TEMPERATURE) &&
        !(sensor_type & SENSOR_TYPE_PRESSURE)) {
        return SYS_EINVAL;
    }

    lps33thw  = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);
    if (lps33thw->cfg.read_mode != LPS33THW_READ_STREAM) {
        return SYS_EINVAL;
    }

    pdd = &lps33thw->pdd;

    itf = SENSOR_GET_ITF(sensor);

    /* Enable FIFO */
    rc = lps33thw_set_value(itf, LPS33THW_FIFO_CTRL_MODE,
			    LPS33THW_FIFO_CONTINUOUS);
    if (rc) {
        goto err;
    }

   if (pdd->interrupt) {
        return SYS_EBUSY;
    }

    rc = lps33thw_enable_interrupt(sensor, lps33thw_int_irq_handler, sensor);
    if (rc) {
        goto err;
    }

    /* Calculate timeout */
    if (time_ms > 0) {
        rc = os_time_ms_to_ticks(time_ms, &time_ticks);
        if (rc) {
            goto err;
        }
        stop_ticks = os_time_get() + time_ticks;
    }

    for (;;) {
	/* Force at least one read for cases when fifo is disabled */
	rc = lps33thw_wait_interrupt(lps33thw->pdd.interrupt);
	if (rc) {
	    goto err;
	}

	rc = lps33thw_get_regs(itf, LPS33THW_FIFO_STATUS1, 1, &fifo_samples);
	if (rc) {
	    goto err;
	}

	if (fifo_samples == 0)
	    continue;

	do {
	    /* Read fifo samples */
	    rc = lps33thw_read_fifo(itf, &std, &spd);
	    if (rc) {
		goto err;
	    }

	    if (sensor_type & SENSOR_TYPE_PRESSURE) {
		rc = read_func(sensor, data_arg, &spd, SENSOR_TYPE_PRESSURE);
		if (rc) {
		    goto err;
		}
	    }
	    if (sensor_type & SENSOR_TYPE_TEMPERATURE) {
		rc = read_func(sensor, data_arg, &std, SENSOR_TYPE_TEMPERATURE);
		if (rc) {
		    goto err;
		}
	    }
	fifo_samples--;
	} while (fifo_samples > 0);

	if (time_ms > 0 && OS_TIME_TICK_GT(os_time_get(), stop_ticks)) {
	    break;
	}
    }

err:
    /* Disable FIFO */
    rc |= lps33thw_set_value(itf, LPS33THW_FIFO_CTRL_MODE,
			    LPS33THW_FIFO_BYPASS);

    lps33thw_disable_interrupt(sensor);

    return rc;
}

/**
 * Sensor data read
 *
 * @param sensor The sensor object
 * @param type sensor type bitmask
 * @param data_func callback register data function
 * @param data_arg function arguments
 * @param timeout in ms
 *
 * @return 0 on success, non-zero error on failure.
 */
static int
lps33thw_sensor_read(struct sensor *sensor, sensor_type_t type,
        sensor_data_func_t data_func, void *data_arg, uint32_t timeout)
{
    struct lps33thw *lps33thw  = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);

    if (lps33thw->cfg.read_mode == LPS33THW_READ_POLL) {
        return lps33thw_sensor_read_poll(sensor, type, data_func, data_arg);
    }

    return lps33thw_stream_read(sensor, type, data_func, data_arg, timeout);
}

static int
lps33thw_sensor_set_config(struct sensor *sensor, void *cfg)
{
    struct lps33thw* lps33thw = (struct lps33thw *)SENSOR_GET_DEVICE(sensor);

    return lps33thw_config(lps33thw, (struct lps33thw_cfg*)cfg);
}

static int
lps33thw_sensor_get_config(struct sensor *sensor, sensor_type_t type,
        struct sensor_cfg *cfg)
{
    /*
     * If the read isn't looking for pressure or temperature
     * don't do anything.
     */
    if (!(type & (SENSOR_TYPE_PRESSURE | SENSOR_TYPE_TEMPERATURE))) {
        return SYS_EINVAL;
    }

    cfg->sc_valtype = SENSOR_VALUE_TYPE_FLOAT;

    return 0;
}

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
static void
init_node_cb(struct bus_node *bnode, void *arg)
{
    struct sensor_itf *itf = arg;

    lps33thw_init((struct os_dev *)bnode, itf);
}

int
lps33thw_create_i2c_sensor_dev(struct bus_i2c_node *node, const char *name,
                               const struct bus_i2c_node_cfg *i2c_cfg,
                               struct sensor_itf *sensor_itf)
{
    struct lps33thw *dev = (struct lps33thw *)node;
    struct bus_node_callbacks cbs = {
        .init = init_node_cb,
    };
    int rc;

    dev->node_is_spi = false;

    sensor_itf->si_dev = &node->bnode.odev;
    bus_node_set_callbacks((struct os_dev *)node, &cbs);

    rc = bus_i2c_node_create(name, node, i2c_cfg, sensor_itf);

    return rc;
}

int
lps33thw_create_spi_sensor_dev(struct bus_spi_node *node, const char *name,
                               const struct bus_spi_node_cfg *spi_cfg,
                               struct sensor_itf *sensor_itf)
{
    struct lps33thw *dev = (struct lps33thw *)node;
    struct bus_node_callbacks cbs = {
        .init = init_node_cb,
    };
    int rc;

    dev->node_is_spi = true;

    sensor_itf->si_dev = &node->bnode.odev;
    bus_node_set_callbacks((struct os_dev *)node, &cbs);

    rc = bus_spi_node_create(name, node, spi_cfg, sensor_itf);

    return rc;
}
#endif
