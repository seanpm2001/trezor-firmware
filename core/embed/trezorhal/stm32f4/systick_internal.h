#ifndef TREZORHAL_SYSTICK_INTERNAL_H
#define TREZORHAL_SYSTICK_INTERNAL_H

#include <stdint.h>

#include "systick.h"

// Internal function called from interrupt context.
// Handles expired timers and invoked their callbacks.
void systimer_dispatch_expired_timers(uint64_t cycles);

#endif  // TREZORHAL_SYSTICK_INTERNAL_H
