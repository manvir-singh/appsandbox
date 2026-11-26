/* Windows guest support for the independently installed ViGEmBus driver.
 * The bus interface definitions below are based on ViGEmClient's MIT-licensed
 * BusShared.h and Common.h by Nefarius Software Solutions e.U. and Contributors
 * (copyright 2016-2023). See THIRD-PARTY-NOTICES.md. */

#include "guest_gamepad.h"
#include <setupapi.h>
#include <stdlib.h>
#include <winioctl.h>

#pragma comment(lib, "setupapi.lib")

static const GUID vigem_interface = {
    0x96E42B22, 0xF5E9, 0x42F8, {0xB0, 0x43, 0xED, 0x0F, 0x93, 0x2F, 0x01, 0x4F}
};

#define VIGEM_IOCTL(code) CTL_CODE(FILE_DEVICE_BUS_EXTENDER, code, METHOD_BUFFERED, FILE_WRITE_DATA)
#define VIGEM_ATTACH     VIGEM_IOCTL(0x801)
#define VIGEM_DETACH     VIGEM_IOCTL(0x802)
#define VIGEM_VERSION    VIGEM_IOCTL(0x803)
#define VIGEM_WAIT_READY VIGEM_IOCTL(0x804)
#define VIGEM_XUSB_STATE VIGEM_IOCTL(0xA02)

typedef struct {
    ULONG size, serial, type;
    USHORT vendor, product;
} VigemAttach;

typedef struct {
    ULONG size, serial;
    AsbGamepadState state;
} VigemReport;

C_ASSERT(sizeof(VigemAttach) == 16);
C_ASSERT(sizeof(VigemReport) == 20);

static BOOL bus_request(AsbGuestGamepads *pads, DWORD code, void *data, DWORD size)
{
    OVERLAPPED io = {0};
    DWORD transferred;
    io.hEvent = pads->event;
    ResetEvent(io.hEvent);
    if (DeviceIoControl(pads->bus, code, data, size, NULL, 0, &transferred, &io)) return TRUE;
    if (GetLastError() != ERROR_IO_PENDING) return FALSE;
    DWORD timeout = code == VIGEM_WAIT_READY ? 5000 : 1000;
    if (WaitForSingleObject(io.hEvent, timeout) == WAIT_OBJECT_0)
        return GetOverlappedResult(pads->bus, &io, &transferred, FALSE);

    CancelIoEx(pads->bus, &io);
    GetOverlappedResult(pads->bus, &io, &transferred, TRUE);
    SetLastError(ERROR_TIMEOUT);
    return FALSE;
}

BOOL asb_guest_gamepads_open(AsbGuestGamepads *pads)
{
    if (pads->bus) return TRUE;
    HDEVINFO devices = SetupDiGetClassDevsW(&vigem_interface, NULL, NULL,
                                           DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devices == INVALID_HANDLE_VALUE) return FALSE;

    pads->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    SP_DEVICE_INTERFACE_DATA device = { sizeof(device) };
    for (DWORD index = 0; pads->event &&
         SetupDiEnumDeviceInterfaces(devices, NULL, &vigem_interface, index, &device); ++index) {
        DWORD size = 0;
        SetupDiGetDeviceInterfaceDetailW(devices, &device, NULL, 0, &size, NULL);
        if (size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) continue;
        SP_DEVICE_INTERFACE_DETAIL_DATA_W *detail = malloc(size);
        if (!detail) break;
        detail->cbSize = sizeof(*detail);
        HANDLE bus = INVALID_HANDLE_VALUE;
        if (SetupDiGetDeviceInterfaceDetailW(devices, &device, detail, size, NULL, NULL)) {
            bus = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, NULL);
        }
        free(detail);
        if (bus == INVALID_HANDLE_VALUE) continue;

        ULONG version[] = { sizeof(version), 1 };
        pads->bus = bus;
        if (bus_request(pads, VIGEM_VERSION, version, sizeof(version))) break;
        CloseHandle(bus);
        pads->bus = NULL;
    }
    SetupDiDestroyDeviceInfoList(devices);
    if (!pads->bus) asb_guest_gamepads_close(pads);
    return pads->bus != NULL;
}

void asb_guest_gamepads_close(AsbGuestGamepads *pads)
{
    /* The driver removes all devices owned by this bus handle when it closes. */
    if (pads->bus) CloseHandle(pads->bus);
    if (pads->event) CloseHandle(pads->event);
    ZeroMemory(pads, sizeof(*pads));
}

static BOOL attach_gamepad(AsbGuestGamepads *pads, unsigned slot)
{
    /* Try other serial numbers if a virtual pad from another program uses one. */
    for (ULONG serial = slot + 1; serial <= 64; serial += INPUT_GAMEPAD_SLOTS) {
        const ULONG xbox360_wired = 0;
        VigemAttach attach = { sizeof(attach), serial, xbox360_wired, 0x045E, 0x028E };
        if (bus_request(pads, VIGEM_ATTACH, &attach, sizeof(attach))) {
            ULONG ready[] = { sizeof(ready), serial };
            if (!bus_request(pads, VIGEM_WAIT_READY, ready, sizeof(ready))) return FALSE;
            pads->serials[slot] = serial;
            return TRUE;
        }
        DWORD error = GetLastError();
        if (error != ERROR_INVALID_PARAMETER && error != ERROR_ALREADY_EXISTS) return FALSE;
    }
    return FALSE;
}

static BOOL submit_state(AsbGuestGamepads *pads, unsigned slot, AsbGamepadState state)
{
    VigemReport report = { sizeof(report), pads->serials[slot], state };
    UINT32 bit = 1u << slot;
    if (bus_request(pads, VIGEM_XUSB_STATE, &report, sizeof(report))) {
        pads->pending &= ~bit;
        return TRUE;
    }
    if (GetLastError() != ERROR_NO_MORE_ITEMS) return FALSE;

    /* ViGEmBus only caches a changed XUSB report when a guest USB read is
     * pending. Keep the latest state until the driver can deliver it. */
    if (!pads->pending) pads->retry_at = GetTickCount64() + ASB_GAMEPAD_RETRY_MS;
    pads->pending_state[slot] = state;
    pads->pending |= bit;
    return TRUE;
}

BOOL asb_guest_gamepads_retry(AsbGuestGamepads *pads)
{
    ULONGLONG now = GetTickCount64();
    if (!pads->pending || now < pads->retry_at) return TRUE;
    pads->retry_at = now + ASB_GAMEPAD_RETRY_MS;
    for (unsigned slot = 0; slot < INPUT_GAMEPAD_SLOTS; ++slot) {
        if ((pads->pending & (1u << slot)) && !submit_state(pads, slot, pads->pending_state[slot]))
            return FALSE;
    }
    return TRUE;
}

BOOL asb_guest_gamepads_receive(AsbGuestGamepads *pads, const InputPacket *packet)
{
    if (packet->type == INPUT_GAMEPAD_DISCONNECT) {
        unsigned slot = packet->param1;
        if (slot >= INPUT_GAMEPAD_SLOTS || packet->param2 || packet->param3 || !pads->serials[slot])
            return TRUE;
        ULONG detach[] = { sizeof(detach), pads->serials[slot] };
        if (!bus_request(pads, VIGEM_DETACH, detach, sizeof(detach))) return FALSE;
        pads->serials[slot] = 0;
        pads->pending &= ~(1u << slot);
        return TRUE;
    }
    if (packet->type == INPUT_GAMEPAD_RESET) {
        if (packet->param1 || packet->param2 || packet->param3) return TRUE;
        const AsbGamepadState neutral = {0};
        for (unsigned slot = 0; slot < INPUT_GAMEPAD_SLOTS; ++slot)
            if (pads->serials[slot] && !submit_state(pads, slot, neutral)) return FALSE;
        return TRUE;
    }
    unsigned slot = packet->type - INPUT_GAMEPAD_STATE;
    if (slot >= INPUT_GAMEPAD_SLOTS) return TRUE;
    return (pads->serials[slot] || attach_gamepad(pads, slot)) &&
           submit_state(pads, slot, asb_gamepad_state(packet));
}
