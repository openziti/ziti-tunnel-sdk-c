

#include <stdint.h>
#include <ziti/netif_driver.h>

#ifndef _Out_cap_c_
#define _Out_cap_c_(n)
#endif

#ifndef _Ret_bytecount_
#define _Ret_bytecount_(n)
#endif

#include <wintun.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>
#include <netioapi.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <combaseapi.h>

#include "tun.h"

#define ZITI_TUN_GUID L"2cbfd72d-370c-43b0-b0cd-c8f092a7e134"
#define ZITI_TUN L"ziti-tun0"

struct netif_handle_s {
    wchar_t name[MAX_ADAPTER_NAME];
    NET_LUID luid;
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

static int tun_add_route(netif_handle tun, const char *dest);
static int tun_del_route(netif_handle tun, const char *dest);
int set_dns(netif_handle tun, uint32_t dns_ip);

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
    DWORD Version = WintunGetRunningDriverVersion();
    ZITI_LOG(INFO, "Wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tun");
        }
        return NULL;
    }
    BOOL rr;
    GUID adapterGuid;
    IIDFromString(ZITI_TUN_GUID, &adapterGuid);
    WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(L"Ziti", ZITI_TUN);
    if (adapter) {
        WintunDeleteAdapter(adapter, true, &rr);
    }

    tun->adapter = WintunCreateAdapter(L"Ziti", ZITI_TUN, &adapterGuid, NULL);
    if (!tun->adapter) {
        DWORD err = GetLastError();
        snprintf(error, error_len, "Failed to create adapter: %d", err);
        return NULL;
    }

    WintunGetAdapterLUID(tun->adapter, &tun->luid);
    WintunGetAdapterName(tun->adapter, tun->name);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    AddressRow.InterfaceLuid = tun->luid;
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = tun_ip;
    AddressRow.OnLinkPrefixLength = 16;
    DWORD err = CreateUnicastIpAddressEntry(&AddressRow);
    if (err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS)
    {
        snprintf(error, error_len, "Failed to set IP address: %d", err);
        tun_close(tun);
        return NULL;
    }

    tun->session = WintunStartSession(tun->adapter, WINTUN_MAX_RING_CAPACITY);
    if (!tun->session) {
        err = GetLastError();
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

    driver->handle       = tun;
    driver->setup        = tun_setup_read;
    driver->write        = tun_write;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_del_route;
    driver->close        = tun_close;

    if (dns_ip) {
        set_dns(tun, dns_ip);
    }

    if (cidr) {
        tun_add_route(tun, cidr);
    }

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
    netif_handle tun = h;
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

static int parse_route(PIP_ADDRESS_PREFIX pfx, const char *route) {
    int ip[4];
    int bits;
    sscanf(route, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);

    pfx->PrefixLength = bits;
    pfx->Prefix.Ipv4.sin_family = AF_INET;
    pfx->Prefix.Ipv4.sin_addr.S_un.S_addr = (ip[0]) | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
}

typedef NTSTATUS(__stdcall *route_f)(const MIB_IPFORWARD_ROW2*);

static DWORD tun_do_route(netif_handle tun, const char *dest, route_f rt_f) {
    MIB_IPFORWARD_ROW2 rt;
    InitializeIpForwardEntry(&rt);

    rt.InterfaceLuid = tun->luid;
    parse_route(&rt.DestinationPrefix, dest);

    return rt_f(&rt);
}

int tun_add_route(netif_handle tun, const char *dest) {
    ZITI_LOG(INFO, "adding route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, CreateIpForwardEntry2);
    if (rc != 0 && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to add route %d err=%d", rc, err);
    }
    return 0;
}

int tun_del_route(netif_handle tun, const char *dest) {
    ZITI_LOG(INFO, "removing route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, DeleteIpForwardEntry2);
    if (rc != 0) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to delete route %d err=%d", rc, err);
    }
    return 0;
}

int set_dns(netif_handle tun, uint32_t dns_ip) {
    // TODO maybe call winapi SetInterfaceDnsSetting
    char cmd[1024];
    char ip[4];
    memcpy(ip, &dns_ip, 4);
    snprintf(cmd, sizeof(cmd),
             "powershell -Command Set-DnsClientServerAddress "
             "-InterfaceAlias %ls "
             "-ServerAddress %d.%d.%d.%d",
             tun->name, ip[0], ip[1], ip[2], ip[3]);
    ZITI_LOG(INFO, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "set DNS: %d(err=%d)", rc, GetLastError());
    }
    return rc;
}
