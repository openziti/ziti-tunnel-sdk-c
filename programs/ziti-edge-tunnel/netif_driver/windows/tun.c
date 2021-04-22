

#include <stdint.h>
#include <ziti/netif_driver.h>

#define _Out_cap_c_(n)
#define _Ret_bytecount_(n)

#include <wintun.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>

#include "tun.h"


struct netif_handle_s {
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;

    uv_thread_t reader;
    uv_async_t *read_available;
    HANDLE read_complete;

    packet_cb on_packet;
    void *netif;
};

static int tun_close(struct netif_handle_s *tun);
static int tun_setup_read(netif_handle tun, uv_loop_t *loop, packet_cb on_packet, void *netif);
static ssize_t tun_write(netif_handle tun, const void *buf, size_t len);

static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
static WINTUN_DELETE_POOL_DRIVER_FUNC WintunDeletePoolDriver;
static WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
static WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;
static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
static WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
static WINTUN_SET_ADAPTER_NAME_FUNC WintunSetAdapterName;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;
static WINTUN_SET_LOGGER_FUNC WintunSetLogger;
static WINTUN_START_SESSION_FUNC WintunStartSession;
static WINTUN_END_SESSION_FUNC WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket;

static uv_once_t wintunInit;
static HMODULE WINTUN;

static void InitializeWintun(void)
{
    HMODULE Wintun =
            LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return;
#define X(Name, Type) ((Name = (Type)GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC) ||
        X(WintunDeleteAdapter, WINTUN_DELETE_ADAPTER_FUNC) ||
        X(WintunDeletePoolDriver, WINTUN_DELETE_POOL_DRIVER_FUNC) ||
        X(WintunEnumAdapters, WINTUN_ENUM_ADAPTERS_FUNC) ||
        X(WintunFreeAdapter, WINTUN_FREE_ADAPTER_FUNC) ||
        X(WintunOpenAdapter, WINTUN_OPEN_ADAPTER_FUNC) ||
        X(WintunGetAdapterLUID, WINTUN_GET_ADAPTER_LUID_FUNC) ||
        X(WintunGetAdapterName, WINTUN_GET_ADAPTER_NAME_FUNC) ||
        X(WintunSetAdapterName, WINTUN_SET_ADAPTER_NAME_FUNC) ||
        X(WintunGetRunningDriverVersion, WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC) ||
        X(WintunSetLogger, WINTUN_SET_LOGGER_FUNC) ||
        X(WintunStartSession, WINTUN_START_SESSION_FUNC) ||
        X(WintunEndSession, WINTUN_END_SESSION_FUNC) ||
        X(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC) ||
    X(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC) ||
    X(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC) ||
    X(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC) ||
    X(WintunSendPacket, WINTUN_SEND_PACKET_FUNC))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        Wintun = NULL;
    }

    WINTUN = Wintun;
}

netif_driver tun_open(struct uv_loop_s *loop, uint32_t tun_ip, uint32_t dns_ip, const char *cidr, char *error, size_t error_len) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    uv_once(&wintunInit, InitializeWintun);
    if (WINTUN == NULL) {
        strcpy_s(error, error_len, "Failed to load wintun.dll");
        return NULL;
    }

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tun");
        }
        return NULL;
    }

    GUID ExampleGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    tun->adapter = WintunOpenAdapter(L"Ziti", L"tun0");
    if (!tun->adapter) {
        tun->adapter = WintunCreateAdapter(L"Ziti", L"tun0", &ExampleGuid, NULL);
        if (!tun->adapter) {
            DWORD err = GetLastError();
            snprintf(error, error_len, "Failed to create adapter: %d", err);
            return NULL;
        }
    }

    tun->session = WintunStartSession(tun->adapter, WINTUN_MAX_RING_CAPACITY);
    if (!tun->session) {
        DWORD err = GetLastError();
        snprintf(error, error_len, "Failed to start session: %d", err);
        return NULL;
    }

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
            tun_close(tun);
        }
        return NULL;
    }
    ZITI_LOG(DEBUG, "tun=%p, adapter=%p, session=%p", tun, tun->adapter, tun->session);

    driver->handle       = tun;
    driver->setup        = tun_setup_read;
    driver->write        = tun_write;
    driver->add_route    = NULL; // TODO tun_add_route;
    driver->delete_route = NULL; // TODO tun_delete_route;
    driver->close        = tun_close;

//    run_command("ip link set %s up", tun->name);
//    run_command("ip addr add %s dev %s", inet_ntoa(*(struct in_addr*)&tun_ip), tun->name);
//
//    if (dns_ip) {
//        init_dns_maintainer(loop, tun->name, dns_ip);
//    }
//
//    if (dns_block) {
//        run_command("ip route add %s dev %s", dns_block, tun->name);
//    }


    //strcpy_s(error, error_len, "TODO: Implement me!");
    return driver;
}

static int tun_close(struct netif_handle_s *tun) {
    if (tun == NULL) {
        return 0;
    }

    if (tun->session) {
        WintunEndSession(tun->session);
        tun->session = NULL;
    }

    if (tun->adapter) {
        WintunFreeAdapter(tun->adapter);
        tun->adapter = NULL;
    }
    free(tun);
    return 0;
}

static void tun_reader(void *h) {
    ZITI_LOG(INFO, "starting read notify thread");
    netif_handle tun = h;
    ZITI_LOG(DEBUG, "tun=%p, adapter=%p, session=%p", tun, tun->adapter, tun->session);

    HANDLE readEv = WintunGetReadWaitEvent(tun->session);
    if (!readEv) {
        DWORD err = GetLastError();
        ZITI_LOG(ERROR, "failed to get ReadWaitEvent from(%p) err=%d", readEv, tun->session, err);
        return;
    }

    while(true) {
        DWORD rc = WaitForSingleObject(readEv, INFINITE);
        if (rc != WAIT_OBJECT_0) {
            DWORD err = GetLastError();
            ZITI_LOG(ERROR, "failed waiting for wintun read event(%p) from(%p) %d(err=%d)", readEv, tun->adapter, rc, err);
            break;
        }

        ZITI_LOG(TRACE, "read available");
        uv_async_send(tun->read_available);
    }
}

static void tun_read(uv_async_t *ar) {
    ZITI_LOG(VERBOSE, "starting read");
    netif_handle tun = ar->data;

    for (int i = 0; i < 128; i++) {
        DWORD len;
        BYTE *packet = WintunReceivePacket(tun->session, &len);
        
        if (packet) {
            tun->on_packet((const char*)packet, len, tun->netif);
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                // done reading
                SetEvent(tun->read_complete);
            } else {
                ZITI_LOG(ERROR, "failed to receive packet: %d", error);
            }
            break;
        }
    }
}

int tun_setup_read(netif_handle tun, uv_loop_t *loop, packet_cb on_packet, void *netif) {
    ZITI_LOG(DEBUG, "tun=%p, adapter=%p, session=%p", tun, tun->adapter, tun->session);

    tun->on_packet = on_packet;
    tun->netif = netif;

    tun->read_available = calloc(1, sizeof(uv_async_t));
    uv_async_init(loop, tun->read_available, tun_read);
    tun->read_available->data = tun;

    tun->read_complete = CreateEventW(NULL, TRUE, FALSE, NULL);
    uv_thread_create(&tun->reader, tun_reader, tun);
    return 0;
}

ssize_t tun_write(netif_handle tun, const void *buf, size_t len) {
    BYTE* packet = WintunAllocateSendPacket(tun->session, len);
    memcpy(packet, buf, len);
    WintunSendPacket(tun->session, packet);
    return 0;
}