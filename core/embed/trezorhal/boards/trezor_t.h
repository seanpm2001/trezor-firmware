#ifndef _TREZOR_T_H
#define _TREZOR_T_H

#define HSE_8MHZ

#define DISPLAY_RESX 240
#define DISPLAY_RESY 240

#define USE_SD_CARD 1
#define USE_I2C 1
#define USE_TOUCH 1
#define USE_SBU 1
#define USE_RGB_COLORS 1
#define USE_BACKLIGHT 1
#define USE_DISP_I8080_8BIT_DW 1

#include "displays/panels/lx154a2422.h"
#include "displays/st7789v.h"
#define DISPLAY_IDENTIFY 1
#define DISPLAY_TE_PORT GPIOD
#define DISPLAY_TE_PIN GPIO_PIN_12
#define TRANSFORM_TOUCH_COORDS lx154a2422_transform_touch_coords

#define BACKLIGHT_PWM_FREQ 50000
#define BACKLIGHT_PWM_TIM TIM1
#define BACKLIGHT_PWM_TIM_CLK_EN __HAL_RCC_TIM1_CLK_ENABLE
#define BACKLIGHT_PWM_TIM_AF GPIO_AF1_TIM1
#define BACKLIGHT_PWM_TIM_OCMODE TIM_OCMODE_PWM2
#define BACKLIGHT_PWM_TIM_CHANNEL TIM_CHANNEL_1
#define BACKLIGHT_PWM_TIM_CCR CCR1
#define BACKLIGHT_PWM_PIN GPIO_PIN_7
#define BACKLIGHT_PWM_PORT GPIOA
#define BACKLIGHT_PWM_PORT_CLK_EN __HAL_RCC_GPIOA_CLK_ENABLE

#define I2C_COUNT 1
#define I2C_INSTANCE_1 I2C1
#define I2C_INSTANCE_1_CLK_EN __HAL_RCC_I2C1_CLK_ENABLE
#define I2C_INSTANCE_1_CLK_DIS __HAL_RCC_I2C1_CLK_DISABLE
#define I2C_INSTANCE_1_PIN_AF GPIO_AF4_I2C1
#define I2C_INSTANCE_1_SDA_PORT GPIOB
#define I2C_INSTANCE_1_SDA_PIN GPIO_PIN_7
#define I2C_INSTANCE_1_SDA_CLK_EN __HAL_RCC_GPIOB_CLK_ENABLE
#define I2C_INSTANCE_1_SCL_PORT GPIOB
#define I2C_INSTANCE_1_SCL_PIN GPIO_PIN_6
#define I2C_INSTANCE_1_SCL_CLK_EN __HAL_RCC_GPIOB_CLK_ENABLE
#define I2C_INSTANCE_1_RESET_FLG RCC_APB1RSTR_I2C1RST

#define TOUCH_I2C_NUM 0
#define TOUCH_RST_PORT GPIOC
#define TOUCH_RST_PIN GPIO_PIN_5
#define TOUCH_INT_PORT GPIOC
#define TOUCH_INT_PIN GPIO_PIN_4
#define TOUCH_ON_PORT GPIOB
#define TOUCH_ON_PIN GPIO_PIN_10

#define SD_DETECT_PORT GPIOC
#define SD_DETECT_PIN GPIO_PIN_13
#define SD_ENABLE_PORT GPIOC
#define SD_ENABLE_PIN GPIO_PIN_0

#endif  //_TREZOR_T_H
