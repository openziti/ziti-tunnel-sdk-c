/*
 * rawsock_windows.c - TAP-Windows raw Ethernet socket.
 *
 * Discovers the first TAP-Windows adapter from the registry, opens the
 * device file with overlapped I/O, and sets the link to UP so the tap
 * driver starts accepting frames.
 *
 * The ifname argument to rawsock_open() is ignored on Windows; the first
 * TAP adapter found in the registry is used automatically.
 *
 * Based on the capture.c pattern used in ziti-tunnel-sdk-c tap.c driver.
 */

#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ---------- TAP-Windows IOCTL / registry constants ---------- */

#define TAP_WIN_COMPONENT_ID        "tap0901"
#define ADAPTER_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define TAP_WIN_IOCTL_GET_MAC \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct rawsock_s {
    HANDLE  dev;        /* TAP device handle (overlapped) */
    uint8_t mac[6];

    OVERLAPPED ov_read;
    OVERLAPPED ov_write;

    /* Pending read buffer (one frame buffered from ReadFile) */
    uint8_t  rbuf[2048];
    DWORD    rbuf_len;
    BOOL     read_pending;
};

/* Find the GUID of the first TAP adapter from the registry. */
static int find_tap_guid(char *guid_out, size_t guid_size,
                          char *error, size_t errlen)
{
    HKEY adapter_key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0,
                      KEY_READ, &adapter_key) != ERROR_SUCCESS) {
        snprintf(error, errlen, "RegOpenKeyEx(adapter_key) failed");
        return -1;
    }

    int found = 0;
    for (DWORD idx = 0; !found; idx++) {
        char subkey_name[256];
        DWORD subkey_len = sizeof(subkey_name);
        if (RegEnumKeyExA(adapter_key, idx, subkey_name, &subkey_len,
                          NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        /* Open the subkey and check ComponentId */
        HKEY dev_key;
        char path[512];
        snprintf(path, sizeof(path), "%s\\%s", ADAPTER_KEY, subkey_name);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0,
                          KEY_READ, &dev_key) != ERROR_SUCCESS)
            continue;

        char component_id[256] = {0};
        DWORD val_len = sizeof(component_id);
        DWORD val_type;
        if (RegQueryValueExA(dev_key, "ComponentId", NULL, &val_type,
                             (LPBYTE)component_id, &val_len) == ERROR_SUCCESS) {
            if (_stricmp(component_id, TAP_WIN_COMPONENT_ID) == 0) {
                /* Read the NetCfgInstanceId (GUID) */
                char net_cfg_guid[256] = {0};
                val_len = sizeof(net_cfg_guid);
                if (RegQueryValueExA(dev_key, "NetCfgInstanceId", NULL, &val_type,
                                     (LPBYTE)net_cfg_guid, &val_len) == ERROR_SUCCESS) {
                    snprintf(guid_out, guid_size, "%s", net_cfg_guid);
                    found = 1;
                }
            }
        }
        RegCloseKey(dev_key);
    }

    RegCloseKey(adapter_key);

    if (!found) {
        snprintf(error, errlen,
                 "No TAP-Windows adapter found. Install OpenVPN TAP driver "
                 "(tap-windows6 / tap0901).");
        return -1;
    }
    return 0;
}

rawsock_t *rawsock_open(const char *ifname, char *error, size_t errlen)
{
    (void)ifname; /* ignored on Windows */

    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);

    rawsock_t *rs = calloc(1, sizeof(*rs));
    if (!rs) { snprintf(error, errlen, "out of memory"); return NULL; }
    rs->dev = INVALID_HANDLE_VALUE;

    /* Locate TAP adapter GUID */
    char guid[256];
    if (find_tap_guid(guid, sizeof(guid), error, errlen) < 0) {
        free(rs);
        return NULL;
    }

    /* Open the TAP device */
    char dev_path[512];
    snprintf(dev_path, sizeof(dev_path), "\\\\.\\Global\\%s.tap", guid);

    rs->dev = CreateFileA(dev_path,
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                          NULL);
    if (rs->dev == INVALID_HANDLE_VALUE) {
        snprintf(error, errlen, "CreateFile(%s): error %lu", dev_path, GetLastError());
        free(rs);
        return NULL;
    }

    /* Get MAC address from TAP driver */
    DWORD bytes_returned;
    if (!DeviceIoControl(rs->dev, TAP_WIN_IOCTL_GET_MAC,
                         rs->mac, sizeof(rs->mac),
                         rs->mac, sizeof(rs->mac),
                         &bytes_returned, NULL)) {
        snprintf(error, errlen, "GET_MAC ioctl: error %lu", GetLastError());
        goto fail;
    }

    /* Set media status to connected (UP) */
    ULONG status = 1;
    if (!DeviceIoControl(rs->dev, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status),
                         &status, sizeof(status),
                         &bytes_returned, NULL)) {
        snprintf(error, errlen, "SET_MEDIA_STATUS ioctl: error %lu", GetLastError());
        goto fail;
    }

    /* Initialise overlapped structures */
    memset(&rs->ov_read,  0, sizeof(rs->ov_read));
    memset(&rs->ov_write, 0, sizeof(rs->ov_write));
    rs->ov_read.hEvent  = CreateEvent(NULL, TRUE, FALSE, NULL);
    rs->ov_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!rs->ov_read.hEvent || !rs->ov_write.hEvent) {
        snprintf(error, errlen, "CreateEvent: error %lu", GetLastError());
        goto fail;
    }

    rs->read_pending = FALSE;
    return rs;

fail:
    if (rs->ov_read.hEvent)  CloseHandle(rs->ov_read.hEvent);
    if (rs->ov_write.hEvent) CloseHandle(rs->ov_write.hEvent);
    CloseHandle(rs->dev);
    free(rs);
    return NULL;
}

void rawsock_close(rawsock_t *rs)
{
    if (!rs) return;
    if (rs->dev != INVALID_HANDLE_VALUE) {
        CancelIoEx(rs->dev, NULL);
        CloseHandle(rs->dev);
    }
    if (rs->ov_read.hEvent)  CloseHandle(rs->ov_read.hEvent);
    if (rs->ov_write.hEvent) CloseHandle(rs->ov_write.hEvent);
    free(rs);
}

int rawsock_send(rawsock_t *rs, const uint8_t *frame, size_t len)
{
    ResetEvent(rs->ov_write.hEvent);
    DWORD written = 0;
    if (!WriteFile(rs->dev, frame, (DWORD)len, &written, &rs->ov_write)) {
        if (GetLastError() != ERROR_IO_PENDING) return -1;
        if (!GetOverlappedResult(rs->dev, &rs->ov_write, &written, TRUE))
            return -1;
    }
    return 0;
}

int rawsock_recv(rawsock_t *rs, uint8_t *buf, size_t buflen, int timeout_ms)
{
    /* Issue a read if none is pending */
    if (!rs->read_pending) {
        ResetEvent(rs->ov_read.hEvent);
        rs->rbuf_len = 0;
        DWORD got = 0;
        if (!ReadFile(rs->dev, rs->rbuf, sizeof(rs->rbuf), &got, &rs->ov_read)) {
            if (GetLastError() != ERROR_IO_PENDING) return -1;
            rs->read_pending = TRUE;
        } else {
            rs->rbuf_len = got;
            /* Synchronous completion — fall through */
        }
    }

    if (rs->read_pending) {
        DWORD wait_ms = (timeout_ms > 0) ? (DWORD)timeout_ms : INFINITE;
        DWORD w = WaitForSingleObject(rs->ov_read.hEvent, wait_ms);
        if (w == WAIT_TIMEOUT) return 0;
        if (w != WAIT_OBJECT_0) return -1;

        DWORD got = 0;
        if (!GetOverlappedResult(rs->dev, &rs->ov_read, &got, FALSE)) return -1;
        rs->rbuf_len    = got;
        rs->read_pending = FALSE;
    }

    if (rs->rbuf_len == 0) return 0;

    size_t copy = (rs->rbuf_len < (DWORD)buflen) ? rs->rbuf_len : (DWORD)buflen;
    memcpy(buf, rs->rbuf, copy);
    rs->rbuf_len = 0;
    return (int)copy;
}

void rawsock_get_mac(rawsock_t *rs, uint8_t mac[6])
{
    memcpy(mac, rs->mac, 6);
}
