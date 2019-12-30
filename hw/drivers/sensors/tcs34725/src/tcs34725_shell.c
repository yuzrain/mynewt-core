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
#include "os/mynewt.h"
#include "console/console.h"
#include "shell/shell.h"
#include "hal/hal_gpio.h"
#include "tcs34725/tcs34725.h"
#include "tcs34725_priv.h"
#include "parse/parse.h"

#if MYNEWT_VAL(TCS34725_CLI)
static int tcs34725_shell_cmd(int argc, char **argv);

static struct shell_cmd tcs34725_shell_cmd_struct = {
    .sc_cmd = "tcs34725",
    .sc_cmd_func = tcs34725_shell_cmd
};

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
static struct sensor_itf g_sensor_itf;
#else
static struct sensor_itf g_sensor_itf = {
    .si_type = MYNEWT_VAL(TCS34725_SHELL_ITF_TYPE),
    .si_num = MYNEWT_VAL(TCS34725_SHELL_ITF_NUM),
    .si_addr = MYNEWT_VAL(TCS34725_SHELL_ITF_ADDR)
};
#endif

static int
tcs34725_shell_err_too_many_args(char *cmd_name)
{
    console_printf("Error: too many arguments for command \"%s\"\n",
                   cmd_name);
    return SYS_EINVAL;
}

static int
tcs34725_shell_err_unknown_arg(char *cmd_name)
{
    console_printf("Error: unknown argument \"%s\"\n",
                   cmd_name);
    return SYS_EINVAL;
}

static int
tcs34725_shell_err_invalid_arg(char *cmd_name)
{
    console_printf("Error: invalid argument \"%s\"\n",
                   cmd_name);
    return SYS_EINVAL;
}

static int
tcs34725_shell_help(void)
{
    console_printf("%s cmd [flags...]\n", tcs34725_shell_cmd_struct.sc_cmd);
    console_printf("cmd:\n");
    console_printf("\tr    [n_samples]\n");
    console_printf("\tgain [0: 1|1: 4|2: 16|3: 60]\n");
    console_printf("\ttime [0: 2.4|1: 24|2: 50|3: 101|4: 154|5: 700]\n");
    console_printf("\ten   [0|1]\n");
    console_printf("\tint  pin [p_num(0..255)]\n");
    console_printf("\tint  on|off|clr\n");
    console_printf("\tint  set [rate(0..15)] [lower(0..65535)] [upper(0..65535)]\n");
    console_printf("\tdump\n");

    return 0;
}

static int
tcs34725_shell_cmd_read(int argc, char **argv)
{
    uint16_t r;
    uint16_t g;
    uint16_t b;
    uint16_t c;
    uint16_t samples = 1;
    uint16_t val;
    int rc;
    struct tcs34725 tcs34725;
    uint8_t int_time;
    int delay_ticks;

    if (argc > 3) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    /* Check if more than one sample requested */
    if (argc == 3) {
        val = parse_ll_bounds(argv[2], 1, UINT16_MAX, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[2]);
        }
        samples = (uint16_t)val;
    }

    while(samples--) {

        rc = tcs34725_get_integration_time(&g_sensor_itf, &int_time);
        if (rc) {
            goto err;
        }

        /* Set a delay for the integration time */
        switch (int_time)
        {
            case TCS34725_INTEGRATIONTIME_2_4MS:
                delay_ticks = 3;
                break;
            case TCS34725_INTEGRATIONTIME_24MS:
                delay_ticks = 24;
                break;
            case TCS34725_INTEGRATIONTIME_50MS:
                delay_ticks = 50;
                break;
            case TCS34725_INTEGRATIONTIME_101MS:
                delay_ticks = 101;
                break;
            case TCS34725_INTEGRATIONTIME_154MS:
                delay_ticks = 154;
                break;
            case TCS34725_INTEGRATIONTIME_700MS:
                delay_ticks = 700;
                break;
            default:
                /*
                 * If the integration time specified is not from the config,
                 * it will get considered as valid inetgration time in ms
                 */
                delay_ticks = 700;
                break;
        }

        os_time_delay((delay_ticks * OS_TICKS_PER_SEC)/1000 + 1);

        rc = tcs34725_get_rawdata(&g_sensor_itf, &r, &g, &b, &c, &tcs34725);
        if (rc) {
            goto err;
        }

        console_printf("r: %u g: %u b: %u c: %u \n", r, g, b, c);
    }

    return 0;
err:
    console_printf("Read failed: %d\n", rc);
    return rc;
}


static int
tcs34725_shell_cmd_gain(int argc, char **argv)
{
    uint8_t val;
    uint8_t gain;
    int rc;

    if (argc > 3) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    /* Display the gain */
    if (argc == 2) {
        rc = tcs34725_get_gain(&g_sensor_itf, &gain);
        if (rc) {
            goto err;
        }
        console_printf("\tgain [0: 1|1: 4|2: 16|3: 60]\n");
        console_printf("%u\n", gain);
    }

    /* Update the gain */
    if (argc == 3) {
        val = parse_ll_bounds(argv[2], 0, 3, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[2]);
        }
        rc = tcs34725_set_gain(&g_sensor_itf, val);
        if (rc) {
            goto err;
        }
    }

    return 0;
err:
    return rc;
}


static int
tcs34725_shell_cmd_time(int argc, char **argv)
{
    uint8_t time;
    uint8_t val;
    int rc;

    if (argc > 3) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    /* Display the integration time */
    if (argc == 2) {
        rc = tcs34725_get_integration_time(&g_sensor_itf, &time);
        if (rc) {
            goto err;
        }

        switch (time) {
            case TCS34725_INTEGRATIONTIME_2_4MS:
                console_printf("2.4\n");
                break;
            case TCS34725_INTEGRATIONTIME_24MS:
                console_printf("24\n");
                break;
            case TCS34725_INTEGRATIONTIME_50MS:
                console_printf("50\n");
                break;
            case TCS34725_INTEGRATIONTIME_101MS:
                console_printf("101\n");
                break;
            case TCS34725_INTEGRATIONTIME_154MS:
                console_printf("154\n");
                break;
            case TCS34725_INTEGRATIONTIME_700MS:
                console_printf("700\n");
                break;
            default:
                assert(0);
                break;
        }
    }

    /* Set the integration time */
    if (argc == 3) {
        val = parse_ll_bounds(argv[2], 0, 5, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[2]);
        }

        switch(val) {
            case 0:
                time = TCS34725_INTEGRATIONTIME_2_4MS;
                break;
            case 1:
                time = TCS34725_INTEGRATIONTIME_24MS;
                break;
            case 2:
                time = TCS34725_INTEGRATIONTIME_50MS;
                break;
            case 3:
                time = TCS34725_INTEGRATIONTIME_101MS;
                break;
            case 4:
                time = TCS34725_INTEGRATIONTIME_154MS;
                break;
            case 5:
                time = TCS34725_INTEGRATIONTIME_700MS;
                break;
            default:
                assert(0);
        }

        rc = tcs34725_set_integration_time(&g_sensor_itf, time);
        if (rc) {
            goto err;
        }
    }

    return 0;
err:
    return rc;
}


static int
tcs34725_shell_cmd_int(int argc, char **argv)
{
    int rc;
    int pin;
    uint16_t val;
    uint16_t lower;
    uint16_t upper;

    if (argc > 6) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    if (argc == 2) {
        rc = tcs34725_get_int_limits(&g_sensor_itf, &lower, &upper);
        if (rc) {
            return rc;
        }
        console_printf("Interrupt lower limit: %u upper limit: %u",
                       lower, upper);
        return 0;
    }

    /* Enable the interrupt */
    if (argc == 3 && strcmp(argv[2], "on") == 0) {
        return tcs34725_enable_interrupt(&g_sensor_itf, 1);
    }

    /* Disable the interrupt */
    if (argc == 3 && strcmp(argv[2], "off") == 0) {
        return tcs34725_enable_interrupt(&g_sensor_itf, 0);
    }

    /* Clear the interrupt on 'clr' */
    if (argc == 3 && strcmp(argv[2], "clr") == 0) {
        return tcs34725_clear_interrupt(&g_sensor_itf);
    }

    /* Configure the interrupt on 'set' */
    if (argc == 3 && strcmp(argv[2], "set") == 0) {
        /* Get lower threshold */
        val = parse_ll_bounds(argv[4], 0, UINT16_MAX, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[4]);
        }
        lower = val;
        /* Get upper threshold */
        val = parse_ll_bounds(argv[5], 0, UINT16_MAX, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[5]);
        }
        upper = val;
        /* Set the values */
        rc = tcs34725_set_int_limits(&g_sensor_itf, lower, upper);
        console_printf("Configured interrupt as:\n");
        console_printf("\tlower: %u\n", lower);
        console_printf("\tupper: %u\n", upper);
        return rc;
    }

    /* Setup INT pin on 'pin' */
    if (argc == 4 && strcmp(argv[2], "pin") == 0) {
        /* Get the pin number */
        val = parse_ll_bounds(argv[3], 0, 0xFF, &rc);
        if (rc) {
            return tcs34725_shell_err_invalid_arg(argv[3]);
        }
        pin = (int)val;
        /* INT is open drain, pullup is required */
        rc = hal_gpio_init_in(pin, HAL_GPIO_PULL_UP);
        assert(rc == 0);
        console_printf("Set pin \"%d\" to INPUT with pull up enabled\n", pin);
        return 0;
    }

    /* Unknown command */
    return tcs34725_shell_err_invalid_arg(argv[2]);
}


static int
tcs34725_shell_cmd_en(int argc, char **argv)
{
    char *endptr;
    long lval;
    int rc;
    uint8_t is_enabled;

    rc = 0;
    if (argc > 3) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    /* Display current enable state */
    if (argc == 2) {
        rc = tcs34725_get_enable(&g_sensor_itf, &is_enabled);
        if (rc) {
            console_printf("Cannot get enable state of the sensor\n");
            goto err;
        }
        console_printf("%u\n", is_enabled);
    }

    /* Update the enable state */
    if (argc == 3) {
        lval = strtol(argv[2], &endptr, 10); /* Base 10 */
        if (*endptr == '\0' && lval >= 0 && lval <= 1) {
                tcs34725_enable(&g_sensor_itf, lval);
        } else {
            return tcs34725_shell_err_invalid_arg(argv[2]);
        }
    }

    return 0;
err:
    return rc;
}

static void tcs34725_shell_dump_reg(const char *name, uint8_t addr)
{
    uint8_t val = 0;
    int rc;

    rc = tcs34725_read8(&g_sensor_itf, addr, &val);
    if (rc == 0) {
        console_printf("0x%02X (%s): 0x%02X\n", addr, name, val);
    } else {
        console_printf("0x%02X (%s): failed (%d)\n", addr, name, rc);
    }
}

#define DUMP_REG(name) tcs34725_shell_dump_reg(#name, TCS34725_REG_ ## name)

static int
tcs34725_shell_cmd_dump(int argc, char **argv)
{
    if (argc > 2) {
        return tcs34725_shell_err_too_many_args(argv[1]);
    }

    /* Dump all the register values for debug purposes */
    DUMP_REG(ENABLE);
    DUMP_REG(ATIME);
    DUMP_REG(WTIME);
    DUMP_REG(AILTL);
    DUMP_REG(AILTH);
    DUMP_REG(AIHTL);
    DUMP_REG(AIHTH);
    DUMP_REG(PERS);
    DUMP_REG(CONFIG);
    DUMP_REG(CONTROL);
    DUMP_REG(ID);
    DUMP_REG(STATUS);
    DUMP_REG(CDATAL);
    DUMP_REG(CDATAH);
    DUMP_REG(RDATAL);
    DUMP_REG(RDATAH);
    DUMP_REG(GDATAL);
    DUMP_REG(GDATAH);
    DUMP_REG(BDATAL);
    DUMP_REG(BDATAH);

    return 0;
}

static int
tcs34725_shell_cmd(int argc, char **argv)
{
    if (argc == 1) {
        return tcs34725_shell_help();
    }

    /* Read command (get a new data sample) */
    if (argc > 1 && strcmp(argv[1], "r") == 0) {
        return tcs34725_shell_cmd_read(argc, argv);
    }

    /* Gain command */
    if (argc > 1 && strcmp(argv[1], "gain") == 0) {
        return tcs34725_shell_cmd_gain(argc, argv);
    }

    /* Integration time command */
    if (argc > 1 && strcmp(argv[1], "time") == 0) {
        return tcs34725_shell_cmd_time(argc, argv);
    }

    /* Enable */
    if (argc > 1 && strcmp(argv[1], "en") == 0) {
        return tcs34725_shell_cmd_en(argc, argv);
    }

    /* Interrupt */
    if (argc > 1 && strcmp(argv[1], "int") == 0) {
        return tcs34725_shell_cmd_int(argc, argv);
    }

    /* Debug */
    if (argc > 1 && strcmp(argv[1], "dumpreg") == 0) {
        return tcs34725_shell_cmd_dump(argc, argv);
    }

    return tcs34725_shell_err_unknown_arg(argv[1]);
}

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)

struct tcs34725 tcs34725_raw;

static const struct bus_i2c_node_cfg tcs34725_raw_cfg = {
    .node_cfg = {
        .bus_name = MYNEWT_VAL(TCS34725_SHELL_ITF_BUS),
    },
    .addr = MYNEWT_VAL(TCS34725_SHELL_ITF_ADDR),
    .freq = 400,
};

#endif

int
tcs34725_shell_init(void)
{
    int rc;

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
    struct os_dev *dev = NULL;

    g_sensor_itf.si_dev = (struct os_dev *)&tcs34725_raw;
    rc = bus_i2c_node_create("tcs34725_raw", &tcs34725_raw.i2c_node,
                             &tcs34725_raw_cfg, &g_sensor_itf);
    if (rc == 0) {
        dev = os_dev_open("tcs34725_raw", 0, NULL);
    }
    if (rc != 0 || dev == NULL) {
        console_printf("Failed to create tcs34725_raw device\n");
    }
#endif
    rc = shell_cmd_register(&tcs34725_shell_cmd_struct);
    SYSINIT_PANIC_ASSERT(rc == 0);

    return rc;
}

#endif
