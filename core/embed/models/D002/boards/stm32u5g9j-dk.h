#ifndef STM32U5A9J_DK_H_
#define STM32U5A9J_DK_H_

#define VDD_1V8 1

#define DISPLAY_COLOR_MODE DMA2D_OUTPUT_ARGB8888

#define I2C_COUNT 2
#define I2C_INSTANCE_0 I2C5
#define I2C_INSTANCE_0_CLK_EN __HAL_RCC_I2C5_CLK_ENABLE
#define I2C_INSTANCE_0_CLK_DIS __HAL_RCC_I2C5_CLK_DISABLE
#define I2C_INSTANCE_0_PIN_AF GPIO_AF2_I2C5
#define I2C_INSTANCE_0_SDA_PORT GPIOH
#define I2C_INSTANCE_0_SDA_PIN GPIO_PIN_4
#define I2C_INSTANCE_0_SDA_CLK_EN __HAL_RCC_GPIOH_CLK_ENABLE
#define I2C_INSTANCE_0_SCL_PORT GPIOH
#define I2C_INSTANCE_0_SCL_PIN GPIO_PIN_5
#define I2C_INSTANCE_0_SCL_CLK_EN __HAL_RCC_GPIOH_CLK_ENABLE
#define I2C_INSTANCE_0_RESET_REG &RCC->APB1RSTR2
#define I2C_INSTANCE_0_RESET_BIT RCC_APB1RSTR2_I2C5RST
#define I2C_INSTANCE_0_EV_IRQHandler I2C5_EV_IRQHandler
#define I2C_INSTANCE_0_ER_IRQHandler I2C5_ER_IRQHandler
#define I2C_INSTANCE_0_EV_IRQn I2C5_EV_IRQn
#define I2C_INSTANCE_0_ER_IRQn I2C5_ER_IRQn
#define I2C_INSTANCE_0_GUARD_TIME 0

#define I2C_INSTANCE_1 I2C2
#define I2C_INSTANCE_1_CLK_EN __HAL_RCC_I2C2_CLK_ENABLE
#define I2C_INSTANCE_1_CLK_DIS __HAL_RCC_I2C2_CLK_DISABLE
#define I2C_INSTANCE_1_PIN_AF GPIO_AF4_I2C2
#define I2C_INSTANCE_1_SDA_PORT GPIOF
#define I2C_INSTANCE_1_SDA_PIN GPIO_PIN_0
#define I2C_INSTANCE_1_SDA_CLK_EN __HAL_RCC_GPIOF_CLK_ENABLE
#define I2C_INSTANCE_1_SCL_PORT GPIOF
#define I2C_INSTANCE_1_SCL_PIN GPIO_PIN_1
#define I2C_INSTANCE_1_SCL_CLK_EN __HAL_RCC_GPIOF_CLK_ENABLE
#define I2C_INSTANCE_1_RESET_REG &RCC->APB1RSTR1
#define I2C_INSTANCE_1_RESET_BIT RCC_APB1RSTR1_I2C2RST
#define I2C_INSTANCE_1_EV_IRQHandler I2C2_EV_IRQHandler
#define I2C_INSTANCE_1_ER_IRQHandler I2C2_ER_IRQHandler
#define I2C_INSTANCE_1_EV_IRQn I2C2_EV_IRQn
#define I2C_INSTANCE_1_ER_IRQn I2C2_ER_IRQn
#define I2C_INSTANCE_1_GUARD_TIME 0

#define TOUCH_I2C_INSTANCE 0
#define NPM1300_I2C_INSTANCE 1
#define STWLC38_I2C_INSTANCE 1

#endif  // STM32U5A9J_DK_H_
