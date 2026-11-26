#pragma once

#include <windows.h>
#include "../../src/core/protocol.h"

#define ASB_GAMEPAD_RETRY_MS 16

typedef struct {
    HANDLE bus, event;
    ULONG serials[INPUT_GAMEPAD_SLOTS];
    AsbGamepadState pending_state[INPUT_GAMEPAD_SLOTS];
    UINT32 pending;
    ULONGLONG retry_at;
} AsbGuestGamepads;

BOOL asb_guest_gamepads_open(AsbGuestGamepads *pads);
void asb_guest_gamepads_close(AsbGuestGamepads *pads);
BOOL asb_guest_gamepads_receive(AsbGuestGamepads *pads, const InputPacket *packet);
BOOL asb_guest_gamepads_retry(AsbGuestGamepads *pads);
