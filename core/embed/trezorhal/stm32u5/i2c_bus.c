/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include STM32_HAL_H
#include TREZOR_BOARD

#include <string.h>

#include "common.h"
#include "i2c_bus.h"
#include "irq.h"
#include "mpu.h"
#include "systemview.h"
#include "systimer.h"

#ifdef KERNEL_MODE

// Using calculation from STM32CubeMX
// PCLKx as source, assumed 160MHz
// Fast mode, freq = 400kHz, Rise time = 250ns, Fall time = 100ns
// Fast mode, freq = 200kHz, Rise time = 250ns, Fall time = 100ns
// SCLH and SCLL are manually modified to achieve more symmetric clock
#define I2C_TIMING_400000_Hz 0x30D22728
#define I2C_TIMING_200000_Hz 0x30D2595A
#define I2C_TIMING I2C_TIMING_200000_Hz

// We expect the I2C bus to be running at ~200kHz
// and max response time of the device is 1000us
#define I2C_BUS_CHAR_TIMEOUT (50 + 5)  // us
#define I2C_BUS_OP_TIMEOUT 1000        // us

#define I2C_BUS_TIMEOUT(n) \
  ((I2C_BUS_CHAR_TIMEOUT * (1 + n) + I2C_BUS_OP_TIMEOUT + 999) / 1000)

// I2C bus hardware definition
typedef struct {
  // I2C controller registers
  I2C_TypeDef* regs;
  // SCL pin GPIO port
  GPIO_TypeDef* scl_port;
  // SDA pin GPIO port
  GPIO_TypeDef* sda_port;
  // SCL pin number
  uint16_t scl_pin;
  // SDA pin number
  uint16_t sda_pin;
  // Alternate function for SCL and SDA pins
  uint8_t pin_af;
  // Register for I2C controller reset
  volatile uint32_t* reset_reg;
  // Reset bit specific for this I2C controller
  uint32_t reset_bit;
  // I2C event IRQ number
  uint32_t ev_irq;
  // I2C error IRQ number
  uint32_t er_irq;
  // Guard time [us] between STOP and START condition.
  // If zero, the guard time is not used.
  uint16_t guard_time;
} i2c_bus_def_t;

// I2C bus hardware definitions
static const i2c_bus_def_t g_i2c_bus_def[I2C_COUNT] = {
    {
        .regs = I2C_INSTANCE_0,
        .scl_port = I2C_INSTANCE_0_SCL_PORT,
        .sda_port = I2C_INSTANCE_0_SDA_PORT,
        .scl_pin = I2C_INSTANCE_0_SCL_PIN,
        .sda_pin = I2C_INSTANCE_0_SDA_PIN,
        .pin_af = I2C_INSTANCE_0_PIN_AF,
        .reset_reg = I2C_INSTANCE_0_RESET_REG,
        .reset_bit = I2C_INSTANCE_0_RESET_BIT,
        .ev_irq = I2C_INSTANCE_0_EV_IRQn,
        .er_irq = I2C_INSTANCE_0_ER_IRQn,
        .guard_time = I2C_INSTANCE_0_GUARD_TIME,
    },
#ifdef I2C_INSTANCE_1
    {
        .regs = I2C_INSTANCE_1,
        .scl_port = I2C_INSTANCE_1_SCL_PORT,
        .sda_port = I2C_INSTANCE_1_SDA_PORT,
        .scl_pin = I2C_INSTANCE_1_SCL_PIN,
        .sda_pin = I2C_INSTANCE_1_SDA_PIN,
        .pin_af = I2C_INSTANCE_1_PIN_AF,
        .reset_reg = I2C_INSTANCE_1_RESET_REG,
        .reset_bit = I2C_INSTANCE_1_RESET_BIT,
        .ev_irq = I2C_INSTANCE_1_EV_IRQn,
        .er_irq = I2C_INSTANCE_1_ER_IRQn,
        .guard_time = I2C_INSTANCE_1_GUARD_TIME,
    },
#endif
#ifdef I2C_INSTANCE_2
    {
        .regs = I2C_INSTANCE_2,
        .scl_port = I2C_INSTANCE_2_SCL_PORT,
        .sda_port = I2C_INSTANCE_2_SDA_PORT,
        .scl_pin = I2C_INSTANCE_2_SCL_PIN,
        .sda_pin = I2C_INSTANCE_2_SDA_PIN,
        .pin_af = I2C_INSTANCE_2_PIN_AF,
        .reset_reg = I2C_INSTANCE_2_RESET_REG,
        .reset_bit = I2C_INSTANCE_2_RESET_BIT,
        .ev_irq = I2C_INSTANCE_2_EV_IRQn,
        .er_irq = I2C_INSTANCE_2_ER_IRQn,
        .guard_time = I2C_INSTANCE_2_GUARD_TIME,
    },
#endif
};

struct i2c_bus {
  // Number of references to the bus
  // (0 means the bus is not initialized)
  uint32_t refcount;

  // Hardware definition
  const i2c_bus_def_t* def;

  // Timer for timeout handling
  systimer_t* timer;

  // Head of the packet queue
  // (this packet is currently being processed)
  i2c_packet_t* queue_head;
  // Tail of the packet queue
  // (this packet is the last in the queue)
  i2c_packet_t* queue_tail;

  // Next operation index in the current packet
  // == 0 => no operation is being processed
  // == queue_head->op_count => no more operations
  int next_op;

  // Points to the data buffer of the current operation
  uint8_t* buff_ptr;
  // Remaining number of bytes of the buffer to transfer
  uint16_t buff_size;
  // Remaining number of bytes of the current operation
  // (if the transfer is split into multiple operations it
  //  may be different from buff_size)
  uint16_t transfer_size;
  // For case of split transfer, points to the next operation
  // that is part of the current transfer
  int transfer_op;

  // Set if the STOP condition is requested after the current operation
  // when data transfer is completed.
  bool stop_requested;
  // Set if pending transaction is being aborted
  bool abort_pending;
  // Set if NACK was detected
  bool nack;
  // Data for clearing TXIS interrupt flag
  // during an invalid or abort state
  uint8_t dummy_data;

  // Flag indicating that the completion callback is being executed
  bool callback_executed;

  // The last time [us] the STOP condition was issued
  uint64_t stop_time;
};

// I2C bus driver instances
static i2c_bus_t g_i2c_bus_driver[I2C_COUNT] = {0};

// Check if the I2C bus pointer is valid
static inline bool i2c_bus_ptr_valid(const i2c_bus_t* bus) {
  if (bus >= &g_i2c_bus_driver[0] && bus < &g_i2c_bus_driver[I2C_COUNT]) {
    uintptr_t offset = (uintptr_t)bus - (uintptr_t)&g_i2c_bus_driver[0];
    if (offset % sizeof(i2c_bus_t) == 0) {
      return bus->refcount > 0;
    }
  }
  return false;
}

// forward declarations
static void i2c_bus_timer_callback(void* context);
static void i2c_bus_head_continue(i2c_bus_t* bus);

static void i2c_bus_unlock(i2c_bus_t* bus) {
  const i2c_bus_def_t* def = bus->def;

  GPIO_InitTypeDef GPIO_InitStructure = {0};

  // Set SDA and SCL high
  HAL_GPIO_WritePin(def->sda_port, def->sda_pin, GPIO_PIN_SET);
  HAL_GPIO_WritePin(def->scl_port, def->scl_pin, GPIO_PIN_SET);

  // Configure SDA and SCL as open-drain output
  // and connect to the I2C peripheral
  GPIO_InitStructure.Mode = GPIO_MODE_OUTPUT_OD;
  GPIO_InitStructure.Pull = GPIO_NOPULL;
  GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_LOW;

  GPIO_InitStructure.Pin = def->scl_pin;
  HAL_GPIO_Init(def->scl_port, &GPIO_InitStructure);

  GPIO_InitStructure.Pin = def->sda_pin;
  HAL_GPIO_Init(def->sda_port, &GPIO_InitStructure);

  uint32_t clock_count = 16;

  while ((HAL_GPIO_ReadPin(def->sda_port, def->sda_pin) == GPIO_PIN_RESET) &&
         (clock_count-- > 0)) {
    // Clock SCL
    HAL_GPIO_WritePin(def->scl_port, def->scl_pin, GPIO_PIN_RESET);
    systick_delay_us(10);
    HAL_GPIO_WritePin(def->scl_port, def->scl_pin, GPIO_PIN_SET);
    systick_delay_us(10);
  }
}

static void i2c_bus_deinit(i2c_bus_t* bus) {
  const i2c_bus_def_t* def = bus->def;

  systimer_delete(bus->timer);

  if (bus->def == NULL) {
    return;
  }

  NVIC_DisableIRQ(def->ev_irq);
  NVIC_DisableIRQ(def->er_irq);

  I2C_TypeDef* regs = def->regs;

  // Disable I2C peripheral
  regs->CR1 = 0;

  // Reset I2C peripheral
  *def->reset_reg |= def->reset_bit;
  *def->reset_reg &= ~def->reset_bit;

  bus->def = NULL;
}

static bool i2c_bus_init(i2c_bus_t* bus, int bus_index) {
  memset(bus, 0, sizeof(i2c_bus_t));

  switch (bus_index) {
    case 0:
      // enable I2C clock
      I2C_INSTANCE_0_CLK_EN();
      I2C_INSTANCE_0_SCL_CLK_EN();
      I2C_INSTANCE_0_SDA_CLK_EN();
      break;

#ifdef I2C_INSTANCE_1
    case 1:
      I2C_INSTANCE_1_CLK_EN();
      I2C_INSTANCE_1_SCL_CLK_EN();
      I2C_INSTANCE_1_SDA_CLK_EN();
      break;
#endif

#ifdef I2C_INSTANCE_2
    case 2:
      I2C_INSTANCE_2_CLK_EN();
      I2C_INSTANCE_2_SCL_CLK_EN();
      I2C_INSTANCE_2_SDA_CLK_EN();
      break;
#endif
    default:
      goto cleanup;
  }

  const i2c_bus_def_t* def = &g_i2c_bus_def[bus_index];

  bus->def = def;

  // Unlocks potentially locked I2C bus by
  // generating several clock pulses on SCL while SDA is low
  i2c_bus_unlock(bus);

  GPIO_InitTypeDef GPIO_InitStructure = {0};

  // Configure SDA and SCL as open-drain output
  // and connect to the I2C peripheral
  GPIO_InitStructure.Mode = GPIO_MODE_AF_OD;
  GPIO_InitStructure.Pull = GPIO_NOPULL;
  GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_LOW;

  GPIO_InitStructure.Alternate = def->pin_af;
  GPIO_InitStructure.Pin = def->scl_pin;
  HAL_GPIO_Init(def->scl_port, &GPIO_InitStructure);

  GPIO_InitStructure.Alternate = def->pin_af;
  GPIO_InitStructure.Pin = def->sda_pin;
  HAL_GPIO_Init(def->sda_port, &GPIO_InitStructure);

  // Reset I2C peripheral
  *def->reset_reg |= def->reset_bit;
  *def->reset_reg &= ~def->reset_bit;

  I2C_TypeDef* regs = def->regs;

  // Configure I2C peripheral
  regs->CR1 = 0;
  regs->TIMINGR = I2C_TIMING;
  regs->CR2 = 0;
  regs->OAR1 = 0;
  regs->OAR2 = 0;
  regs->CR1 |= I2C_CR1_PE;

  // Configure I2C interrupts
  regs->CR1 |= I2C_CR1_ERRIE | I2C_CR1_NACKIE | I2C_CR1_STOPIE | I2C_CR1_TCIE |
               I2C_CR1_RXIE | I2C_CR1_TXIE;

  NVIC_SetPriority(def->ev_irq, IRQ_PRI_NORMAL);
  NVIC_SetPriority(def->er_irq, IRQ_PRI_NORMAL);

  NVIC_EnableIRQ(def->ev_irq);
  NVIC_EnableIRQ(def->er_irq);

  bus->timer = systimer_create(i2c_bus_timer_callback, bus);
  if (bus->timer == NULL) {
    goto cleanup;
  }

  return true;

cleanup:
  i2c_bus_deinit(bus);
  return false;
}

i2c_bus_t* i2c_bus_open(uint8_t bus_index) {
  if (bus_index >= I2C_COUNT) {
    return NULL;
  }

  i2c_bus_t* bus = &g_i2c_bus_driver[bus_index];

  if (bus->refcount == 0) {
    if (!i2c_bus_init(bus, bus_index)) {
      return NULL;
    }
  }

  ++bus->refcount;

  return bus;
}

void i2c_bus_close(i2c_bus_t* bus) {
  if (!i2c_bus_ptr_valid(bus)) {
    return;
  }

  if (bus->refcount > 0) {
    if (--bus->refcount == 0) {
      i2c_bus_deinit(bus);
    }
  }
}

i2c_status_t i2c_packet_status(const i2c_packet_t* packet) {
  irq_key_t irq_key = irq_lock();
  i2c_status_t status = packet->status;
  irq_unlock(irq_key);
  return status;
}

i2c_status_t i2c_packet_wait(const i2c_packet_t* packet) {
  while (true) {
    i2c_status_t status = i2c_packet_status(packet);

    if (status != I2C_STATUS_PENDING) {
      return status;
    }

    // Enter sleep mode and wait for any interrupt
    __WFI();
  }
}

static uint8_t i2c_bus_read_buff(i2c_bus_t* bus) {
  if (bus->transfer_size > 0) {
    while (bus->buff_size == 0 && bus->transfer_op < bus->next_op) {
      i2c_op_t* op = &bus->queue_head->ops[bus->transfer_op++];
      if (op->flags & I2C_FLAG_EMBED) {
        bus->buff_ptr = op->data;
        bus->buff_size = MIN(op->size, sizeof(op->data));
      } else {
        bus->buff_ptr = op->ptr;
        bus->buff_size = op->size;
      }
    }

    --bus->transfer_size;

    if (bus->buff_size > 0) {
      --bus->buff_size;
      return *bus->buff_ptr++;
    }
  }

  return 0;
}

static void i2c_bus_write_buff(i2c_bus_t* bus, uint8_t data) {
  if (bus->transfer_size > 0) {
    while (bus->buff_size == 0 && bus->transfer_op < bus->next_op) {
      i2c_op_t* op = &bus->queue_head->ops[bus->transfer_op++];
      if (op->flags & I2C_FLAG_EMBED) {
        bus->buff_ptr = op->data;
        bus->buff_size = MIN(op->size, sizeof(op->data));
      } else {
        bus->buff_ptr = op->ptr;
        bus->buff_size = op->size;
      }
    }

    --bus->transfer_size;

    if (bus->buff_size > 0) {
      *bus->buff_ptr++ = data;
      --bus->buff_size;
    }
  }
}

// Invokes the packet completion callback
static inline void i2c_bus_invoke_callback(i2c_bus_t* bus, i2c_packet_t* packet,
                                           i2c_status_t status) {
  packet->status = status;
  if (packet->callback) {
    bus->callback_executed = true;
    packet->callback(packet->context, packet);
    bus->callback_executed = false;
  }
}

// Appends the packet to the end of the queue
// Returns true if the queue was empty before
// Expects disabled IRQ or calling from IRQ context
static inline bool i2c_bus_add_packet(i2c_bus_t* bus, i2c_packet_t* packet) {
  if (bus->queue_tail == NULL) {
    bus->queue_head = packet;
    bus->queue_tail = packet;
    return true;
  } else {
    bus->queue_tail->next = packet;
    bus->queue_tail = packet;
    return false;
  }
}

// Removes the packet from the queue (if present)
// Returns true if the removed we removed head of the queue
// Expects disabled IRQ or calling from IRQ context
static inline bool i2c_bus_remove_packet(i2c_bus_t* bus, i2c_packet_t* packet) {
  if (packet == bus->queue_head) {
    // Remove head of the queue
    bus->queue_head = packet->next;
    // If the removed packet was also the tail, reset the tail
    if (bus->queue_tail == packet) {
      bus->queue_tail = NULL;
    }
    packet->next = NULL;
    return true;
  }

  // Remove from the middle or tail of the queue
  i2c_packet_t* p = bus->queue_head;
  while (p->next != NULL && p->next != packet) {
    p = p->next;
  }

  if (p->next == packet) {
    // The packet found in the queue, remove it
    p->next = packet->next;
    // Update the tail if necessary
    if (bus->queue_tail == packet) {
      bus->queue_tail = p;
    }
    packet->next = NULL;
  }

  return false;
}

i2c_status_t i2c_bus_submit(i2c_bus_t* bus, i2c_packet_t* packet) {
  if (!i2c_bus_ptr_valid(bus) || packet == NULL) {
    // Invalid bus or packet
    return I2C_STATUS_ERROR;
  }

  if (packet->next != NULL) {
    // Packet is already queued
    return I2C_STATUS_ERROR;
  }

  packet->status = I2C_STATUS_PENDING;

  // Insert packet into the queue
  irq_key_t irq_key = irq_lock();
  if (i2c_bus_add_packet(bus, packet)) {
    // The queue was empty, start the operation
    if (!bus->callback_executed && !bus->abort_pending) {
      i2c_bus_head_continue(bus);
    }
  }
  irq_unlock(irq_key);

  return I2C_STATUS_OK;
}

void i2c_bus_abort(i2c_bus_t* bus, i2c_packet_t* packet) {
  if (!i2c_bus_ptr_valid(bus) || packet == NULL) {
    // Invalid bus or packet
    return;
  }

  irq_key_t irq_key = irq_lock();

  if (packet->status == I2C_STATUS_PENDING) {
    if (i2c_bus_remove_packet(bus, packet) && bus->next_op > 0) {
      // The packet was being processed

      if (bus->transfer_size > 0) {
        bus->dummy_data = i2c_bus_read_buff(bus);
      }

      // Reset internal state
      bus->next_op = 0;
      bus->buff_ptr = NULL;
      bus->buff_size = 0;
      bus->transfer_size = 0;
      bus->transfer_op = 0;
      bus->stop_requested = false;

      // Inform interrupt handler about pending abort
      bus->abort_pending = true;

      // Abort operation may fail if the bus is busy or noisy
      // so we need to set a timeout.
      systimer_set(bus->timer, I2C_BUS_TIMEOUT(2));
    }

    packet->status = I2C_STATUS_ABORTED;
  }

  irq_unlock(irq_key);
}

// Completes the current packet by removing it from the queue
// an invoking the completion callback
//
// Must be called with IRQ disabled or from IRQ context
// Expects the operation is finished
static void i2c_bus_head_complete(i2c_bus_t* bus, i2c_status_t status) {
  i2c_packet_t* packet = bus->queue_head;
  if (packet != NULL) {
    // Remove packet from the queue
    i2c_bus_remove_packet(bus, packet);

    // Reset internal state
    bus->next_op = 0;
    bus->buff_ptr = NULL;
    bus->buff_size = 0;
    bus->transfer_size = 0;
    bus->transfer_op = 0;
    bus->stop_requested = false;
    bus->abort_pending = false;

    systimer_unset(bus->timer);

    // Invoke the completion callback
    i2c_bus_invoke_callback(bus, packet, status);
  }
}

// Starts the next operation in the packet by
// programming the I2C controller
//
// Must be called with IRQ disabled or from IRQ context
// Expects no other operation is being processed
static void i2c_bus_head_continue(i2c_bus_t* bus) {
  if (bus->abort_pending) {
    systimer_unset(bus->timer);
    bus->abort_pending = false;
  }

  if (bus->queue_head != NULL) {
    i2c_packet_t* packet = bus->queue_head;

    if (bus->next_op < packet->op_count) {
      i2c_op_t* op = &packet->ops[bus->next_op++];
      I2C_TypeDef* regs = bus->def->regs;

      uint32_t cr2 = regs->CR2;
      cr2 &= ~(I2C_CR2_SADD | I2C_CR2_NBYTES | I2C_CR2_RELOAD |
               I2C_CR2_AUTOEND | I2C_CR2_RD_WRN | I2C_CR2_SADD_Msk);

      // Set device address
      cr2 |= ((packet->address & 0x7F) << 1) << I2C_CR2_SADD_Pos;

      // Get data ptr and its length
      if (op->flags & I2C_FLAG_EMBED) {
        bus->buff_ptr = op->data;
        bus->buff_size = MIN(op->size, sizeof(op->data));
      } else {
        bus->buff_ptr = op->ptr;
        bus->buff_size = op->size;
      }

      // Calculate transfer size
      bus->transfer_size = bus->buff_size;
      bus->transfer_op = bus->next_op;

      // Include following operations in the transfer if:
      // 1) We are not processing the last operation
      // 2) STOP condition is not requested in the current operation
      // 3) START condition is not requested in the next operation
      // 4) The next operation has the same direction

      while ((bus->next_op != packet->op_count) &&
             ((op->flags & I2C_FLAG_STOP) == 0) &&
             (((op + 1)->flags & I2C_FLAG_START) == 0) &&
             (((op + 1)->flags & I2C_FLAG_TX) == (op->flags & I2C_FLAG_TX))) {
        // Move to the next operation
        op = &packet->ops[bus->next_op++];

        if (op->flags & I2C_FLAG_EMBED) {
          bus->transfer_size += MIN(op->size, sizeof(op->data));
        } else {
          bus->transfer_size += op->size;
        }
      }

      if (bus->transfer_size > 0) {
        // I2C controller can handle only 255 bytes at once
        // More data will be handled by the TCR interrupt
        cr2 |= MIN(255, bus->transfer_size) << I2C_CR2_NBYTES_Pos;

        if (bus->transfer_size > 255) {
          cr2 |= I2C_CR2_RELOAD;
        }

        if (op->flags & I2C_FLAG_TX) {
          // Transmitting has priority over receive.
          // Flush TXDR register possibly filled by some previous
          // invalid operation or abort.
          regs->ISR = I2C_ISR_TXE;
        } else if (op->flags & I2C_FLAG_RX) {
          // Receive data from the device
          cr2 |= I2C_CR2_RD_WRN;
        }
      }

      // STOP condition:
      //  1) if it is explicitly requested
      //  2) if it is the last operation in the packet
      bus->stop_requested = ((op->flags & I2C_FLAG_STOP) != 0) ||
                            (bus->next_op == packet->op_count);

      bus->nack = false;

      // START condition
      cr2 |= I2C_CR2_START;

      // Guard time between operations STOP and START condition
      if (bus->def->guard_time > 0) {
        while (systick_us() - bus->stop_time < bus->def->guard_time)
          ;
      }

      regs->CR2 = cr2;

      // Each operation has its own timeout calculated
      // based on the number of bytes to transfer and the bus speed +
      // expected operation overhead
      systimer_set(bus->timer,
                   I2C_BUS_TIMEOUT(bus->transfer_size) + packet->timeout);
    }
  }
}

// Timer callback handling I2C bus timeout
static void i2c_bus_timer_callback(void* context) {
  i2c_bus_t* bus = (i2c_bus_t*)context;

  if (bus->abort_pending) {
    // Packet abort was not completed in time (STOPF was not detected)
    // This may be caused by the bus being busy/noisy.
    I2C_TypeDef* regs = bus->def->regs;

    // Reset the I2C controller
    regs->CR1 &= ~I2C_CR1_PE;
    regs->CR1 |= I2C_CR1_PE;

    // Continue with the next packet
    i2c_bus_head_continue(bus);
  } else {
    // Timeout during normal operation occurred
    i2c_packet_t* packet = bus->queue_head;
    if (packet != NULL) {
      // Determine the status based on the current bus state
      I2C_TypeDef* regs = bus->def->regs;
      i2c_status_t status;
      if ((regs->CR2 & I2C_CR2_START) && (regs->ISR & I2C_ISR_BUSY)) {
        // START condition was issued but the bus is still busy
        status = I2C_STATUS_BUSY;
      } else {
        status = I2C_STATUS_TIMEOUT;
      }

      // Abort pending packet
      i2c_bus_abort(bus, packet);

      // Invoke the completion callback
      i2c_bus_invoke_callback(bus, packet, status);
    }
  }
}

// I2C bus event interrupt handler
static void i2c_bus_ev_handler(i2c_bus_t* bus) {
  I2C_TypeDef* regs = bus->def->regs;

  uint32_t isr = regs->ISR;

  if (isr & I2C_ISR_RXNE) {
    // I2C controller receive buffer is not empty.
    // The interrupt flag is cleared by reading the RXDR register.
    uint8_t received_byte = regs->RXDR;
    if (bus->next_op > 0 && bus->transfer_size > 0) {
      i2c_bus_write_buff(bus, received_byte);
    } else if (bus->abort_pending) {
      regs->CR2 |= I2C_CR2_STOP;
    } else {
      // Invalid state, ignore
    }
  }

  if (isr & I2C_ISR_TXIS) {
    // I2C controller transmit buffer is empty.
    // The interrupt flag is cleared by writing the TXDR register.
    if (bus->next_op > 0 && bus->transfer_size > 0) {
      regs->TXDR = i2c_bus_read_buff(bus);
    } else {
      regs->TXDR = bus->dummy_data;
      if (bus->abort_pending) {
        regs->CR2 |= I2C_CR2_STOP;
      } else {
        // Invalid state, ignore
      }
    }
  }

  if (isr & I2C_ISR_TCR) {
    // Data transfer is partially completed and RELOAD is required
    if (bus->abort_pending) {
      // Packet is being aborted, issue STOP condition
      regs->CR2 &= ~(I2C_CR2_NBYTES | I2C_CR2_RELOAD);
      regs->CR2 |= I2C_CR2_STOP;
    } else if (bus->transfer_size > 0) {
      // There are still some bytes left in the current operation buffer
      uint32_t cr2 = regs->CR2 & ~(I2C_CR2_NBYTES | I2C_CR2_RELOAD);

      cr2 |= MIN(bus->transfer_size, 255) << I2C_CR2_NBYTES_Pos;

      if (bus->transfer_size > 255) {
        // Set RELOAD if we the remaining data is still over
        // the 255 bytes limit
        cr2 |= I2C_CR2_RELOAD;
      }
      regs->CR2 = cr2;
    } else if (bus->queue_head != NULL) {
      // Data transfer is split between two or more operations,
      // continues in the next operation
      i2c_bus_head_continue(bus);
    } else {
      // Invalid state, clear the TCR flag
      regs->CR2 &= ~(I2C_CR2_NBYTES | I2C_CR2_RELOAD);
      regs->CR2 |= I2C_CR2_STOP;
    }
  }

  if (isr & I2C_ISR_TC) {
    // Transfer complete
    if (bus->stop_requested || bus->abort_pending) {
      // Issue stop condition and wait for ISR_STOPF flag
      regs->CR2 |= I2C_CR2_STOP;
    } else if (bus->queue_head != NULL) {
      // Continue with the next operation
      i2c_bus_head_continue(bus);
    } else {
      // Invalid state, clear the TC flag
      regs->CR2 |= I2C_CR2_STOP;
    }
  }

  if (isr & I2C_ISR_NACKF) {
    // Clear the NACKF flag
    regs->ICR = I2C_ICR_NACKCF;
    bus->nack = true;
    // STOP condition is automatically generated
    // by the hardware and the STOPF is set later.
  }

  if (isr & I2C_ISR_STOPF) {
    // Clear the STOPF flag
    regs->ICR = I2C_ICR_STOPCF;

    if (bus->def->guard_time > 0) {
      bus->stop_time = systick_us();
    }

    if (bus->next_op > 0 && bus->next_op == bus->queue_head->op_count) {
      // Last operation in the packet
      i2c_bus_head_complete(bus, bus->nack ? I2C_STATUS_NACK : I2C_STATUS_OK);
    }

    // Continue with the next operation
    // or complete the pending packet and move to the next
    i2c_bus_head_continue(bus);
  }
}

// I2C bus error interrupt handler
static void i2c_bus_er_handler(i2c_bus_t* bus) {
  I2C_TypeDef* regs = bus->def->regs;

  uint32_t isr = regs->ISR;

  // Clear error flags
  regs->ICR = I2C_ICR_BERRCF | I2C_ICR_ARLOCF | I2C_ICR_OVRCF;

  if (isr & I2C_ISR_BERR) {
    // Bus error
    // Ignore and continue with pending operation
  }

  if (isr & I2C_ISR_ARLO) {
    if (bus->next_op > 0) {
      // Arbitration lost, complete packet with error
      i2c_bus_head_complete(bus, I2C_STATUS_ERROR);
      // Start the next packet
      i2c_bus_head_continue(bus);
    } else {
      // Packet aborted or invalid state
    }
  }

  if (isr & I2C_ISR_OVR) {
    // This should not happen in master mode
  }
}

// Interrupt handlers

#ifdef I2C_INSTANCE_0
void I2C_INSTANCE_0_EV_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_ev_handler(&g_i2c_bus_driver[0]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}

void I2C_INSTANCE_0_ER_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_er_handler(&g_i2c_bus_driver[0]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}
#endif

#ifdef I2C_INSTANCE_1
void I2C_INSTANCE_1_EV_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_ev_handler(&g_i2c_bus_driver[1]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}

void I2C_INSTANCE_1_ER_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_er_handler(&g_i2c_bus_driver[1]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}
#endif

#ifdef I2C_INSTANCE_2
void I2C_INSTANCE_2_EV_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_ev_handler(&g_i2c_bus_driver[2]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}

void I2C_INSTANCE_2_ER_IRQHandler(void) {
  SEGGER_SYSVIEW_RecordEnterISR();
  mpu_mode_t mpu_mode = mpu_reconfig(MPU_MODE_DEFAULT);
  i2c_bus_er_handler(&g_i2c_bus_driver[2]);
  mpu_restore(mpu_mode);
  SEGGER_SYSVIEW_RecordExitISR();
}
#endif

#endif  // KERNEL_MODE
