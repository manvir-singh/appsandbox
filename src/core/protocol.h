#ifndef ASB_PROTOCOL_H
#define ASB_PROTOCOL_H

#include <stdint.h>

#define INPUT_MAGIC           0x4E495341u /* ASIN, little-endian */
#define INPUT_READY_MAGIC     0x59445249u /* IRDY */
#define INPUT_MOUSE_MOVE      0
#define INPUT_MOUSE_BUTTON    1
#define INPUT_MOUSE_WHEEL     2
#define INPUT_KEY             3
#define INPUT_KEYBOARD_QUERY  4
#define INPUT_KEYBOARD_REPLY  5
#define INPUT_KEY_PHYSICAL    6
#define INPUT_KEYBOARD_VERSION 2
#define INPUT_MOUSE_QUERY     7
#define INPUT_MOUSE_REPLY     8
#define INPUT_MOUSE_RELATIVE  9
#define INPUT_MOUSE_POSITION_QUERY 10
#define INPUT_MOUSE_POSITION_REPLY 11
#define INPUT_UNICODE          12
#define INPUT_GAMEPAD_QUERY    32
#define INPUT_GAMEPAD_REPLY    33
#define INPUT_GAMEPAD_STATE    34 /* Add a slot index, 0 through 3. */
#define INPUT_GAMEPAD_DISCONNECT 38
#define INPUT_GAMEPAD_RESET    39
#define INPUT_GAMEPAD_VERSION  1
#define INPUT_GAMEPAD_SLOTS    4
#define INPUT_MOUSE_VERSION   1
#define INPUT_MOUSE_NORMALIZED_VERSION 2
#define INPUT_MOUSE_NORMALIZED 1u
#define INPUT_MOUSE_ABSOLUTE_MAX 65535u

#define INPUT_BTN_LEFT        0
#define INPUT_BTN_RIGHT       1
#define INPUT_BTN_MIDDLE      2
#define INPUT_KEY_EXTENDED    1
#define INPUT_KEY_UP          2

/* All packets are 20 little-endian bytes, following the IRDY greeting.
 * QUERY/REPLY: param1 = keyboard version, param2 = echoed request ID, param3 = 0.
 * Without a matching reply, senders retain INPUT_KEY's legacy VK semantics.
 * KEY_PHYSICAL: param2 = set-1 make byte, EXTENDED = E0, UP = release.
 * With scan zero only, param1 identifies a Windows VK non-text function key
 * (Pause/Break, Print Screen, Sleep, or browser/media/launch keys).
 * MOUSE_QUERY/REPLY: param1 = mouse version, param2 = echoed request ID, param3 = 0.
 * Without a matching mouse reply, senders retain absolute mouse movement.
 * MOUSE_RELATIVE: param1/param2 = signed int32 X/Y deltas, param3 = 0.
 * POSITION_QUERY: param1 = request ID, param2/param3 = 0.
 * POSITION_REPLY: param1/param2 = physical guest-screen X/Y, param3 = request ID.
 * Both coordinates are INT32_MIN if the cursor position cannot be read.
 * GAMEPAD_QUERY/REPLY: param1 = gamepad version (0 if unavailable), param2/param3 = 0.
 * GAMEPAD_STATE: Xbox button bits and two byte triggers in param1, signed
 * left X/Y in param2 and right X/Y in param3 (low/high 16 bits).
 * GAMEPAD_DISCONNECT: param1 = slot, param2/param3 = 0.
 * GAMEPAD_RESET: neutralize all connected pads, all parameters zero.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t type;
    uint32_t param1;
    uint32_t param2;
    uint32_t param3;
} InputPacket;

typedef struct {
    uint16_t buttons;
    uint8_t left_trigger, right_trigger;
    int16_t left_x, left_y, right_x, right_y;
} AsbGamepadState;
#pragma pack(pop)

static inline InputPacket asb_gamepad_packet(unsigned slot, const AsbGamepadState *state)
{
    InputPacket packet = { INPUT_MAGIC, INPUT_GAMEPAD_STATE + slot,
        state->buttons | ((uint32_t)state->left_trigger << 16) | ((uint32_t)state->right_trigger << 24),
        (uint16_t)state->left_x | ((uint32_t)(uint16_t)state->left_y << 16),
        (uint16_t)state->right_x | ((uint32_t)(uint16_t)state->right_y << 16) };
    return packet;
}

static inline AsbGamepadState asb_gamepad_state(const InputPacket *packet)
{
    AsbGamepadState state = { (uint16_t)packet->param1,
        (uint8_t)(packet->param1 >> 16), (uint8_t)(packet->param1 >> 24),
        (int16_t)packet->param2, (int16_t)(packet->param2 >> 16),
        (int16_t)packet->param3, (int16_t)(packet->param3 >> 16) };
    return state;
}

#define DISPLAY_GPU_MAGIC     0x50475341u
#define DISPLAY_GPU_VERSION   3
#define DISPLAY_GPU_QUERY     1
#define DISPLAY_GPU_CAPS      2
#define DISPLAY_GPU_OFFER     3
#define DISPLAY_GPU_READY     4
#define DISPLAY_GPU_RESIZE    5
#define DISPLAY_GPU_RESIZED   6
#define DISPLAY_GPU_SNAPSHOT  7
#define DISPLAY_GPU_SLOTS     3
#define DISPLAY_GPU_CAP_RESIZE 1u
#define DISPLAY_GPU_CAP_IVSHMEM 2u
#define DISPLAY_GPU_CAP_FENCE 4u
#define DISPLAY_GPU_CAP_REFRESH 8u
#define DISPLAY_GPU_CAP_SNAPSHOT 16u
/* A QUERY with this bit accepts pixel RLE on the frame stream, independently
 * of GPU sharing. Legacy peers continue to exchange raw pixel payloads. */
#define DISPLAY_GPU_CAP_FRAME_RLE 32u
#define ASB_FRAME_RLE_FLAG 0x80000000u /* high bit of the wire payload length */
/* The sequence high bit advertises that a stream-only guest accepts a QUERY
 * carrying just FRAME_RLE. Older viewers ignore the frame sequence. This
 * lets software-only viewers avoid sending control traffic to older guests. */
#define ASB_FRAME_SEQ_RLE_CAPABLE (UINT64_C(1) << 63)
#define DISPLAY_GPU_FENCE_SLOTS (DISPLAY_GPU_SLOTS * 2)
#define DISPLAY_SIZE_GUEST    0u
#define DISPLAY_SIZE_WINDOW   1u
#define DISPLAY_MIN_WIDTH     1024u
#define DISPLAY_MIN_HEIGHT    768u
#define DISPLAY_MAX_WIDTH     7680u
#define DISPLAY_MAX_HEIGHT    4320u
#define DISPLAY_MIN_REFRESH   24u
#define DISPLAY_MAX_REFRESH   120u

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t type;
    uint64_t session;
    uint64_t handle;
    uint64_t reserved;
    uint32_t process_id;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t vendor_id;
    uint32_t device_id;
    uint32_t status;
    uint32_t version;
    uint32_t slot;
} DisplayGpuPacket;
#pragma pack(pop)

#endif
