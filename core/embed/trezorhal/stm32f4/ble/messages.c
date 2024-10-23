

#ifdef KERNEL_MODE

#include <stdint.h>

#include "ble_hal.h"
#include "int_comm_defs.h"
#include "messages.h"

void send_state_request(void) {
  uint8_t cmd = INTERNAL_CMD_PING;
  ble_hal_int_send(&cmd, sizeof(cmd));
}

void send_advertising_on(bool whitelist) {
  uint8_t data[2];
  data[0] = INTERNAL_CMD_ADVERTISING_ON;
  data[1] = whitelist ? 1 : 0;
  ble_hal_int_send(data, sizeof(data));
}

void send_advertising_off(void) {
  uint8_t cmd = INTERNAL_CMD_ADVERTISING_OFF;
  ble_hal_int_send(&cmd, sizeof(cmd));
}

bool send_erase_bonds(void) {
  if (!ble_hal_firmware_running()) {
    return false;
  }
  uint8_t cmd = INTERNAL_CMD_ERASE_BONDS;
  ble_hal_int_send(&cmd, sizeof(cmd));

  return true;
}

bool send_disconnect(void) {
  if (!ble_hal_firmware_running()) {
    return false;
  }
  uint8_t cmd = INTERNAL_CMD_DISCONNECT;
  ble_hal_int_send(&cmd, sizeof(cmd));

  return true;
}

void send_pairing_reject(void) {
  uint8_t cmd = INTERNAL_CMD_REJECT_PAIRING;
  ble_hal_int_send(&cmd, sizeof(cmd));
}

void send_pairing_accept(void) {
  uint8_t cmd = INTERNAL_CMD_ALLOW_PAIRING;
  ble_hal_int_send(&cmd, sizeof(cmd));
}

#endif
