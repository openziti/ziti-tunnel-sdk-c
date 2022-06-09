

/*
 Copyright 2021 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

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
#include <ziti/model_support.h>

#include "tun.h"

#define ZITI_TUN_GUID L"2cbfd72d-370c-43b0-b0cd-c8f092a7e134"
#define ZITI_TUN L"ziti-tun0"

#define ROUTE_LIFETIME (10 * 60) /* in seconds */
#define ROUTE_REFRESH ((ROUTE_LIFETIME - (ROUTE_LIFETIME/10))*1000)

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

    model_map excluded_routes;
    uv_timer_t route_timer;
};

static int tun_close(struct netif_handle_s *tun);
static int tun_setup_read(netif_handle tun, uv_loop_t *loop, packet_cb on_packet, void *netif);
static ssize_t tun_write(netif_handle tun, const void *buf, size_t len);
static int tun_add_route(netif_handle tun, const char *dest);
static int tun_del_route(netif_handle tun, const char *dest);
int set_dns(netif_handle tun, uint32_t dns_ip);
static int tun_exclude_rt(netif_handle dev, uv_loop_t *loop, const char *dest);
static void if_change_cb(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
static void refresh_routes(uv_timer_t *timer);
static void cleanup_adapters(wchar_t *tun_name);
static HANDLE if_change_handle;

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

static MIB_IPFORWARD_ROW2 default_rt;

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

netif_driver tun_open(struct uv_loop_s *loop, uint32_t tun_ip, const char *cidr, char *error, size_t error_len) {
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
    cleanup_adapters(ZITI_TUN);

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

    NotifyIpInterfaceChange(AF_INET, if_change_cb, tun, TRUE, &if_change_handle);

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

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    AddressRow.InterfaceLuid = tun->luid;
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = tun_ip;

    if (cidr) {
        int bits;
        uint32_t ip[4];
        sscanf(cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
        AddressRow.OnLinkPrefixLength = bits;
    } else {
        AddressRow.OnLinkPrefixLength = 16;
    }
    DWORD err = CreateUnicastIpAddressEntry(&AddressRow);
    if (err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS)
    {
        snprintf(error, error_len, "Failed to set IP address: %d", err);
        tun_close(tun);
        return NULL;
    }

    driver->handle       = tun;
    driver->setup        = tun_setup_read;
    driver->write        = tun_write;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_del_route;
    driver->close        = tun_close;
    driver->exclude_rt   = tun_exclude_rt;
    uv_timer_init(loop, &tun->route_timer);
    tun->route_timer.data = tun;
    uv_unref((uv_handle_t *) &tun->route_timer);
    uv_timer_start(&tun->route_timer, refresh_routes, ROUTE_REFRESH, ROUTE_REFRESH);

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
        WintunDeleteAdapter(tun->adapter, true, NULL);
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
    ZITI_LOG(TRACE, "starting read");
    netif_handle tun = ar->data;

    for (int i = 0; i < 128; i++) {
        DWORD len;
        BYTE *packet = WintunReceivePacket(tun->session, &len);
        
        if (packet) {
            tun->on_packet((const char*)packet, len, tun->netif);
            WintunReleaseReceivePacket(tun->session, packet);
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
    int rc = sscanf_s(route, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
    if (rc < 4) {
        ZITI_LOG(WARN, "invalid IPV4 route spec[%s]", route);
        return -1;
    } else {
        pfx->PrefixLength = rc == 4 ? 32 : bits;

        pfx->Prefix.Ipv4.sin_family = AF_INET;
        pfx->Prefix.Ipv4.sin_addr.S_un.S_addr = (ip[0]) | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
    }
    return 0;
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
    ZITI_LOG(DEBUG, "adding route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, CreateIpForwardEntry2);
    if (rc != 0 && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to add route %d err=%d", rc, err);
    }
    return 0;
}

int tun_del_route(netif_handle tun, const char *dest) {
    ZITI_LOG(DEBUG, "removing route: %s", dest);
    DWORD rc = tun_do_route(tun, dest, DeleteIpForwardEntry2);
    if (rc != 0) {
        DWORD err = GetLastError();
        ZITI_LOG(WARN, "failed to delete route %d err=%d", rc, err);
    }
    return 0;
}

static void if_change_cb(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType) {
    struct netif_handle_s *tun = CallerContext;

    MIB_IPFORWARD_ROW2 rt = {0};
    rt.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    ZITI_LOG(DEBUG, "interface change: if_idx = %d, change = %d", Row ? Row->InterfaceIndex : 0, NotificationType);
    int rc = GetIpForwardEntry2(&rt);
    if (rc == NO_ERROR) {
        if (default_rt.InterfaceIndex != rt.InterfaceIndex) {
            ZITI_LOG(INFO, "default route is now via if_idx[%d]", rt.InterfaceIndex);
            default_rt.InterfaceIndex = rt.InterfaceIndex;
            default_rt.InterfaceLuid = rt.InterfaceLuid;
            default_rt.Metric = rt.Metric;
            default_rt.NextHop = rt.NextHop;

            ZITI_LOG(INFO, "updating excluded routes");
            const char *dest;
            MIB_IPFORWARD_ROW2 *route;
            MODEL_MAP_FOREACH(dest, route, &tun->excluded_routes) {
                route->NextHop = rt.NextHop;
                route->InterfaceIndex = rt.InterfaceIndex;
                route->InterfaceLuid = rt.InterfaceLuid;
                if (SetIpForwardEntry2(route) != NO_ERROR) {
                    char err[256];
                    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  err, sizeof(err), NULL);
                    ZITI_LOG(WARN, "failed to update route[%s]: %d(%s)", dest, rc, err);
                }
            }
        }
    } else {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
        ZITI_LOG(WARN, "failed to get default route: %d(%s)", rc, err);
    }
}

static int tun_exclude_rt(netif_handle dev, uv_loop_t *loop, const char *dest) {

    MIB_IPFORWARD_ROW2 *route = calloc(1, sizeof(MIB_IPFORWARD_ROW2));
    route->DestinationPrefix.Prefix.si_family = AF_INET;
    parse_route(&route->DestinationPrefix, dest);
    int rc = GetIpForwardEntry2(route);
    if (rc == NO_ERROR) {
        ZITI_LOG(DEBUG, "route to %s found", dest);
        DeleteIpForwardEntry2(route);
    }

    route->InterfaceIndex = default_rt.InterfaceIndex;
    route->InterfaceLuid = default_rt.InterfaceLuid;
    route->Metric = 0;
    route->NextHop = default_rt.NextHop;
    route->ValidLifetime = ROUTE_LIFETIME;
    route->PreferredLifetime = ROUTE_LIFETIME;

    rc = CreateIpForwardEntry2(route);
    if (rc != NO_ERROR) {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
        ZITI_LOG(WARN, "failed to create exclusion route: %d(%s)", rc, err);
    }
    model_map_set(&dev->excluded_routes, dest, route);
    return 0;
}

void refresh_routes(uv_timer_t *timer) {
    ZITI_LOG(DEBUG, "refreshing excluded routes");
    struct netif_handle_s *tun = timer->data;
    const char *dest;
    MIB_IPFORWARD_ROW2 *route;
    MODEL_MAP_FOREACH(dest, route, &tun->excluded_routes) {
        ZITI_LOG(DEBUG, "refreshing route to %s", dest);
        int rc = SetIpForwardEntry2(route);
        if (rc != NO_ERROR) {
        char err[256];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      err, sizeof(err), NULL);
            ZITI_LOG(WARN, "failed to create exclusion route[%s]: %d(%s)", dest, rc, err);
        }
    }
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

char* get_tun_name(netif_handle tun) {
    return tun->name;
}

static BOOL CALLBACK
tun_delete_cb(_In_ WINTUN_ADAPTER_HANDLE adapter, _In_ LPARAM param) {
    wchar_t name[32];
    WintunGetAdapterName(adapter, name);
    wchar_t *tun_name = param;
    if (wcsncmp(name, tun_name, wcslen(tun_name)) == 0) {
        WintunDeleteAdapter(adapter, true, NULL);
        ZITI_LOG(INFO, "Deleted wintun adapter %ls", name);
    } else {
        ZITI_LOG(INFO, "Not deleting wintun adapter %ls, name didn't match %ls", name, tun_name);
    }
    // the call back should always return value greater than zero, so the cleanup function will continue
    return 1;
}

static void cleanup_adapters(wchar_t *tun_name) {
    ZITI_LOG(INFO, "Cleaning up orphan wintun adapters");
    WintunEnumAdapters(L"Ziti", tun_delete_cb, tun_name);
}

// close session causes the segmentation fault when the adapter is running
int tun_kill() {
    WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(L"Ziti", ZITI_TUN);
    if (adapter) {
        ZITI_LOG(DEBUG, "Closing wintun adapter");
        WintunDeleteAdapter(adapter, true, NULL);
        WintunFreeAdapter(adapter);
        ZITI_LOG(DEBUG, "Closed wintun adapter");
    }
}
