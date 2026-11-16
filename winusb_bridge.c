/*
 * WinUSB emulation layer for XGPro T48 under Wine.
 *
 * Replaces WINUSB.DLL, patches the IAT to intercept
 * SetupAPI device enumeration and CreateFileA for the T48.
 * Forwards USB I/O to bridge_daemon over TCP localhost.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dbt.h>
#include <wininet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "bridge_proto.h"
#include "xgpro_models.h"

#define MAX_TRANSFER_LEN (16 * 1024 * 1024)
#define BRIDGE_TOKEN_PATH_WINE "\\\\?\\unix\\tmp\\.xgpro-bridge-token"

typedef struct {
    DWORD cbSize;
    GUID  InterfaceClassGuid;
    DWORD Flags;
    ULONG_PTR Reserved;
} MY_SP_DEVICE_INTERFACE_DATA;

typedef struct {
    DWORD cbSize;
    char  DevicePath[260];
} MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A;

/* Device-family identity lives in xgpro_models.h, shared with the daemon.
 * The app's SetupDi GUID selects the profile; CMD_HELLO tells the daemon
 * which PID to open, so the two sides cannot disagree. */
static const xgpro_model_t XGPRO_MODELS[] = {
#define X(pid_, name_, guid_, ei, eip, eo, eop, ue, dop, st, fl) \
    { .pid = pid_, .name = name_, .guid = guid_, \
      .ep_in = ei, .ep_in_peer = eip, .ep_out = eo, .ep_out_peer = eop, \
      .unused_in_ep = ue, .drain_on_opcode = dop, .settle_ms = st, \
      .flags = fl },
    XGPRO_MODEL_TABLE(X)
#undef X
};
#define XGPRO_MODEL_COUNT ((int)(sizeof(XGPRO_MODELS) / sizeof(XGPRO_MODELS[0])))

static int selected_profile = -1;
static volatile LONG sub_started = 0;
static DWORD pipe_timeout_ms[256];   /* PIPE_TRANSFER_TIMEOUT per pipe */
static HWND  notify_hwnd = NULL;            /* window the app registered for WM_DEVICECHANGE */
static GUID  notify_guid;                   /* interface GUID the app registered with */
static BOOL  notify_guid_valid = FALSE;

#define FAKE_HDEVINFO       ((HANDLE)(ULONG_PTR)0xDE000001)

static int profile_index_for_guid(const GUID *guid) {
    for (int i = 0; i < XGPRO_MODEL_COUNT; i++) {
        if (memcmp(guid, &XGPRO_MODELS[i].guid, sizeof(xgpro_guid_t)) == 0)
            return i;
    }
    return -1;
}

static const xgpro_model_t *current_profile(void) {
    if (selected_profile < 0) selected_profile = 0;
    return &XGPRO_MODELS[selected_profile];
}


static int is_verbose(void);
static void dbg(const char *fmt, ...);

/* ---------------------------------------------------------------------
 * TEST-ONLY fake devices.
 *
 * XGPRO_FAKE_DEVICES=N (1..4) makes SetupDi present the real programmer plus
 * N-1 synthetic ones, so the app's own multi-device table and enumeration loop
 * can be exercised without owning several programmers.  The fakes answer only
 * the device-info exchange and return zeros otherwise; they are named FAKE*,
 * never touch libusb, and are off by default.  This is a plumbing test, not
 * evidence about real hardware.
 * --------------------------------------------------------------------- */
#define FAKE_HANDLE_BASE ((ULONG_PTR)0xF0000000)
#define FAKE_MAX 4
static int fake_total_cached = -1;
static volatile int fake_info_pending[FAKE_MAX];

static int fake_total(void)
{
    if (fake_total_cached < 0) {
        const char *e = getenv("XGPRO_FAKE_DEVICES");
        int n = e ? atoi(e) : 1;
        if (n < 1) n = 1;
        if (n > FAKE_MAX) n = FAKE_MAX;
        fake_total_cached = n;
        if (n > 1)
            fprintf(stderr, "[winusb] TEST MODE: %d devices (%d fake), "
                            "no hardware data from the fakes\n", n, n - 1);
    }
    return fake_total_cached;
}

static int fake_index_from_handle(HANDLE h)
{
    ULONG_PTR v = (ULONG_PTR)h;
    if ((v & ~(ULONG_PTR)0xFF) == FAKE_HANDLE_BASE)
        return (int)(v & 0xFF);
    return -1;
}

static HANDLE fake_handle(int idx)
{
    return (HANDLE)(FAKE_HANDLE_BASE | (ULONG_PTR)idx);
}

#define REAL_HANDLE_BASE ((ULONG_PTR)0xF1000000)
static int real_index_from_handle(HANDLE h)
{
    ULONG_PTR v = (ULONG_PTR)h;
    if ((v & ~(ULONG_PTR)0xFF) == REAL_HANDLE_BASE)
        return (int)(v & 0xFF);
    return -1;
}


static const char *fake_device_path(int idx)
{
    static char buf[260];
    const xgpro_model_t *p = current_profile();
    const xgpro_guid_t *g = &p->guid;

    snprintf(buf, sizeof(buf),
             "\\\\?\\USB#VID_A466&PID_%04X#FAKE%d#{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             p->pid, idx, (unsigned long)g->d1, g->d2, g->d3,
             g->d4[0], g->d4[1], g->d4[2], g->d4[3],
             g->d4[4], g->d4[5], g->d4[6], g->d4[7]);
    return buf;
}

static BOOL fake_write_pipe(int idx, UCHAR pipe, PUCHAR buf, ULONG len,
                            PULONG xfer)
{
    if (is_verbose()) {
        char hex[128] = {0};
        ULONG i, off = 0;
        for (i = 0; i < len && i < 32 && off < sizeof(hex) - 4; i++)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x ", buf ? buf[i] : 0);
        dbg("TEST fake %d WritePipe pipe=0x%02x len=%u data=%s", idx, pipe, len, hex);
    }
    if ((pipe == 0x01 || pipe == 0x02) && buf && len >= 1 && buf[0] == 0x00)
        fake_info_pending[idx & (FAKE_MAX - 1)] = 1;
    if (xfer) *xfer = len;
    return TRUE;
}

static BOOL fake_read_pipe(int idx, UCHAR pipe, PUCHAR buf, ULONG len,
                           PULONG xfer)
{
    idx &= (FAKE_MAX - 1);
    if (!buf || len == 0) {
        if (xfer) *xfer = 0;
        return TRUE;
    }
    if ((pipe == 0x81 || pipe == 0x82) && fake_info_pending[idx]) {
        /* Same 41-byte GET_INFO layout the real TL866II+ returns; only the
         * two per-device identity fields are replaced.  The trailing 9 bytes
         * are the firmware/model capability block, not per-unit data. */
        static const uint8_t template_info[41] = {
            0x00, 0x01, 0x21, 0x00, 0x84, 0x02, 0x05, 0x00,
            '2', '0', '7', '7', '0', '0', '6', '4',
            'R', 'J', 'X', 'F', 'K', 'E', 'X', 'Y',
            'K', '6', 'I', 'I', '7', 'R', '5', 'R',
            0x37, 0x43, 0x4f, 0x41, 0xd0, 0x9e, 0x26, 0x84, 0x04
        };
        uint8_t info[41];
        char num[9], ser[17];
        ULONG n;
        memcpy(info, template_info, sizeof(info));
        fake_info_pending[idx] = 0;
        snprintf(num, sizeof(num), "%08d", 90000000 + idx);
        snprintf(ser, sizeof(ser), "FAKE%012d", idx);
        memcpy(&info[8], num, 8);
        memcpy(&info[16], ser, 16);
        n = len < sizeof(info) ? len : sizeof(info);
        memcpy(buf, info, n);
        if (is_verbose()) {
            char hex[128] = {0};
            ULONG i, off = 0;
            for (i = 0; i < n && i < 32 && off < sizeof(hex) - 4; i++)
                off += snprintf(hex + off, sizeof(hex) - off, "%02x ", info[i]);
            dbg("TEST fake %d ReadPipe pipe=0x%02x info %s", idx, pipe, hex);
        }
        if (xfer) *xfer = n;
        return TRUE;
    }
    ULONG n = len > 64 ? 64 : len;
    memset(buf, 0, n);
    if (is_verbose()) dbg("TEST fake %d ReadPipe pipe=0x%02x len=%u -> zeros",
                          idx, pipe, len);
    if (xfer) *xfer = n;
    return TRUE;
}

static int wsa_inited = 0;
static CRITICAL_SECTION bridge_cs;
static int debug_verbose = -1;

static int is_verbose(void) {
    if (debug_verbose < 0)
        debug_verbose = (getenv("XGPRO_DEBUG") != NULL);
    return debug_verbose;
}

static void dbg(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
    fprintf(stderr, "[winusb] %s\n", buf);
}

/* ---------------------------------------------------------------------
 * Connection layer.
 *
 * One TCP connection per device.  The daemon forks a worker per connection,
 * so each worker owns exactly one programmer and its single-device state
 * stays valid; multiple devices never share a libusb handle.  A short-lived
 * control connection is used for enumeration, and the hotplug subscriber has
 * its own connection.
 * --------------------------------------------------------------------- */
typedef struct {
    SOCKET sock;
    int    fake;          /* -1 = real device, >= 0 = test fake index */
    int    index;         /* enumeration slot */
    char   path[BRIDGE_PATH_LEN];
} bridge_conn_t;

typedef struct {
    char     path[BRIDGE_PATH_LEN];
    uint16_t pid;
    int      fake;                   /* -1 = real, >= 0 = fake index */
    char     product[64];
} bridge_enum_t;

static bridge_enum_t enum_devs[BRIDGE_MAX_DEVICES];
static volatile LONG enum_count = 0;
static volatile LONG enum_valid = 0;

static int sock_send_all(SOCKET s, const void *buf, int len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        int n = send(s, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int sock_recv_all(SOCKET s, void *buf, int len)
{
    char *p = (char *)buf;
    while (len > 0) {
        int n = recv(s, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static SOCKET bridge_connect_raw(void)
{
    SOCKET s;
    struct sockaddr_in addr;
    uint8_t token[BRIDGE_TOKEN_LEN];
    DWORD got = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int tries;

    if (!wsa_inited) {
        WSADATA wsa;
        int err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (err != 0) {
            dbg("WSAStartup failed: %d", err);
            return INVALID_SOCKET;
        }
        wsa_inited = 1;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        dbg("socket failed: %d", WSAGetLastError());
        return INVALID_SOCKET;
    }
    {
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
        int bufsize = 256 * 1024;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BRIDGE_PORT);
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */

    /* The launcher starts the daemon just before the app; give it a moment. */
    for (tries = 0; tries < 20; tries++) {
        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            break;
        Sleep(100);
    }
    if (tries == 20) {
        dbg("connect to bridge failed: %d", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    dbg("Connected to bridge daemon on port %d", BRIDGE_PORT);

    hFile = CreateFileA(BRIDGE_TOKEN_PATH_WINE, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        dbg("Failed to open token file: %s (err=%d)", BRIDGE_TOKEN_PATH_WINE, (int)GetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (!ReadFile(hFile, token, BRIDGE_TOKEN_LEN, &got, NULL) ||
        got != BRIDGE_TOKEN_LEN) {
        dbg("Failed to read token file (read %u bytes)", (unsigned)got);
        CloseHandle(hFile);
        closesocket(s);
        return INVALID_SOCKET;
    }
    CloseHandle(hFile);
    if (sock_send_all(s, token, BRIDGE_TOKEN_LEN) < 0) {
        dbg("Failed to send auth token");
        closesocket(s);
        return INVALID_SOCKET;
    }
    dbg("Auth token sent to bridge daemon");
    return s;
}

static int bridge_hello_sock(SOCKET s, uint16_t pid)
{
    bridge_request_t hreq = { CMD_HELLO, 0, 0 };
    bridge_hello_t hello;
    bridge_response_t resp = { 0, 0 };

    hello.version = BRIDGE_PROTO_VERSION;
    hello.pid = pid;
    if (sock_send_all(s, &hreq, sizeof(hreq)) < 0 ||
        sock_send_all(s, &hello, sizeof(hello)) < 0 ||
        sock_recv_all(s, &resp, sizeof(resp)) < 0 || resp.status != 0) {
        dbg("Bridge rejected protocol v%u / PID %04x (status %d, daemon v%u)",
            hello.version, hello.pid, resp.status, resp.length);
        SetLastError(ERROR_REVISION_MISMATCH);
        return -1;
    }
    dbg("Bridge protocol v%u, requested PID %04x", hello.version, hello.pid);
    return 0;
}

static SOCKET bridge_connect_control(uint16_t pid)
{
    SOCKET s = bridge_connect_raw();
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    if (bridge_hello_sock(s, pid) < 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static int bridge_enumerate(void)
{
    uint16_t pid = (selected_profile >= 0) ? XGPRO_MODELS[selected_profile].pid : 0;
    SOCKET s = bridge_connect_control(pid);
    bridge_request_t req = { CMD_ENUMERATE, 0, 0 };
    bridge_response_t resp = { 0, 0 };
    uint32_t count = 0, i;
    int n = 0, target;

    if (s == INVALID_SOCKET) {
        dbg("enumeration: no control connection");
        return -1;
    }
    if (sock_send_all(s, &req, sizeof(req)) < 0 ||
        sock_recv_all(s, &resp, sizeof(resp)) < 0 || resp.status != 0 ||
        sock_recv_all(s, &count, sizeof(count)) < 0) {
        dbg("enumeration failed");
        closesocket(s);
        return -1;
    }
    if (count > BRIDGE_MAX_DEVICES) count = BRIDGE_MAX_DEVICES;
    for (i = 0; i < count; i++) {
        bridge_dev_info_t d;
        if (sock_recv_all(s, &d, sizeof(d)) < 0) break;
        if (pid && d.pid != pid) continue;
        if (n >= BRIDGE_MAX_DEVICES) continue;
        memset(&enum_devs[n], 0, sizeof(enum_devs[n]));
        snprintf(enum_devs[n].path, sizeof(enum_devs[n].path), "%s", d.path);
        snprintf(enum_devs[n].product, sizeof(enum_devs[n].product), "%s", d.product);
        enum_devs[n].pid = d.pid;
        enum_devs[n].fake = -1;
        dbg("enumeration: %s at %s (PID %04x)", d.product, d.path, d.pid);
        n++;
    }
    closesocket(s);

    /* TEST-ONLY: top the list up with fakes so XGPRO_FAKE_DEVICES=N presents
     * N programmers.  The fakes are local to the shim and never touch the
     * daemon or libusb. */
    target = fake_total();
    while (target > 1 && n < target && n < BRIDGE_MAX_DEVICES) {
        int fi = n;
        memset(&enum_devs[n], 0, sizeof(enum_devs[n]));
        snprintf(enum_devs[n].path, sizeof(enum_devs[n].path), "FAKE%d", fi);
        snprintf(enum_devs[n].product, sizeof(enum_devs[n].product), "FAKE%d (test)", fi);
        enum_devs[n].pid = pid;
        enum_devs[n].fake = fi;
        dbg("enumeration: TEST fake %d", fi);
        n++;
    }

    enum_count = n;
    InterlockedExchange(&enum_valid, 1);
    dbg("enumeration: %d device(s)", n);
    return 0;
}

static SOCKET bridge_open_session(const char *path, uint16_t pid)
{
    SOCKET s = bridge_connect_control(pid);
    bridge_request_t req = { CMD_OPEN, 0, 0 };
    bridge_open_t open;
    bridge_response_t resp = { 0, 0 };

    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    memset(&open, 0, sizeof(open));
    if (path) strncpy(open.path, path, sizeof(open.path) - 1);
    if (sock_send_all(s, &req, sizeof(req)) < 0 ||
        sock_send_all(s, &open, sizeof(open)) < 0 ||
        sock_recv_all(s, &resp, sizeof(resp)) < 0 || resp.status != 0) {
        dbg("CMD_OPEN %s failed (status %d)", path ? path : "", resp.status);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static void bridge_close_session(bridge_conn_t *c)
{
    if (!c) return;
    if (c->sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_CLOSE, 0, 0 };
        bridge_response_t resp;
        if (sock_send_all(c->sock, &req, sizeof(req)) == 0)
            sock_recv_all(c->sock, &resp, sizeof(resp));
        closesocket(c->sock);
    }
    free(c);
}

static void session_drop(bridge_conn_t *c)
{
    if (c && c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
}


static const char *real_device_path(int idx)
{
    static char buf[260];
    const xgpro_model_t *p = current_profile();
    const xgpro_guid_t *g = &p->guid;
    char token[BRIDGE_PATH_LEN];
    int i;

    snprintf(token, sizeof(token), "%s",
             (idx >= 0 && idx < (int)enum_count) ? enum_devs[idx].path : "");
    for (i = 0; token[i]; i++)
        if (token[i] == ':') token[i] = '-';

    snprintf(buf, sizeof(buf),
             "\\\\?\\USB#VID_A466&PID_%04X#XGPRO-%s#{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             p->pid, token,
             (unsigned long)g->d1, g->d2, g->d3,
             g->d4[0], g->d4[1], g->d4[2], g->d4[3],
             g->d4[4], g->d4[5], g->d4[6], g->d4[7]);
    return buf;
}

static int enum_index_for_path(const char *upper)
{
    for (int i = 0; i < (int)enum_count; i++) {
        char token[BRIDGE_PATH_LEN], pat[BRIDGE_PATH_LEN + 16];
        char *q;
        if (enum_devs[i].fake >= 0)
            continue;
        strncpy(token, enum_devs[i].path, sizeof(token) - 1);
        token[sizeof(token) - 1] = '\0';
        for (q = token; *q; q++)
            if (*q == ':') *q = '-';
        snprintf(pat, sizeof(pat), "XGPRO-%s", token);
        if (strstr(upper, pat))
            return i;
    }
    return -1;
}

static HANDLE WINAPI my_SetupDiGetClassDevsA(
    const GUID *ClassGuid, const char *Enumerator, HWND hwndParent, DWORD Flags)
{
    if (ClassGuid) {
        int idx = profile_index_for_guid(ClassGuid);
        if (idx >= 0) {
            selected_profile = idx;
            EnterCriticalSection(&bridge_cs);
            bridge_enumerate();
            LeaveCriticalSection(&bridge_cs);
            dbg("SetupDiGetClassDevsA: matched %s GUID -> %d device(s)",
                XGPRO_MODELS[idx].name, (int)enum_count);
            return FAKE_HDEVINFO;
        }
    }
    dbg("SetupDiGetClassDevsA: unknown GUID, returning INVALID_HANDLE_VALUE");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI my_SetupDiEnumDeviceInterfaces(
    HANDLE DeviceInfoSet, void *DeviceInfoData,
    const GUID *InterfaceClassGuid, DWORD MemberIndex,
    MY_SP_DEVICE_INTERFACE_DATA *DeviceInterfaceData)
{
    if (DeviceInfoSet == FAKE_HDEVINFO &&
        MemberIndex < (DWORD)enum_count) {
        dbg("SetupDiEnumDeviceInterfaces: returning %s at index %lu",
            enum_devs[MemberIndex].fake >= 0 ? "FAKE" :
                enum_devs[MemberIndex].product,
            (unsigned long)MemberIndex);
        if (DeviceInterfaceData) {
            DeviceInterfaceData->cbSize = sizeof(MY_SP_DEVICE_INTERFACE_DATA);
            memcpy(&DeviceInterfaceData->InterfaceClassGuid,
                   &current_profile()->guid, sizeof(xgpro_guid_t));
            DeviceInterfaceData->Flags = 1;
            DeviceInterfaceData->Reserved = MemberIndex;
        }
        return TRUE;
    }
    if (getenv("XGPRO_DEBUG"))
        dbg("SetupDiEnumDeviceInterfaces: index=%lu -> ERROR_NO_MORE_ITEMS",
            (unsigned long)MemberIndex);
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

static BOOL WINAPI my_SetupDiGetDeviceInterfaceDetailA(
    HANDLE DeviceInfoSet, MY_SP_DEVICE_INTERFACE_DATA *InterfaceData,
    MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A *DetailData, DWORD DetailDataSize,
    DWORD *RequiredSize, void *DeviceInfoData)
{
    DWORD idx = InterfaceData ? (DWORD)InterfaceData->Reserved : 0;
    const char *path;
    if (idx < (DWORD)enum_count && enum_devs[idx].fake >= 0)
        path = fake_device_path(enum_devs[idx].fake);
    else if (idx < (DWORD)enum_count)
        path = real_device_path((int)idx);
    else
        path = fake_device_path(0);
    DWORD needed = offsetof(MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A, DevicePath) +
                   strlen(path) + 1;
    dbg("SetupDiGetDeviceInterfaceDetailA: needed=%u provided=%u", needed, DetailDataSize);

    if (RequiredSize) *RequiredSize = needed;

    if (!DetailData || DetailDataSize < needed) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    DetailData->cbSize = 5;
    strncpy(DetailData->DevicePath, path, sizeof(DetailData->DevicePath) - 1);
    DetailData->DevicePath[sizeof(DetailData->DevicePath) - 1] = '\0';
    dbg("  -> path: %s", DetailData->DevicePath);
    return TRUE;
}

static BOOL WINAPI my_SetupDiDestroyDeviceInfoList(HANDLE DeviceInfoSet) {
    dbg("SetupDiDestroyDeviceInfoList");
    return TRUE;
}


typedef HANDLE (WINAPI *pfn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static pfn_CreateFileA orig_CreateFileA = NULL;

static HANDLE WINAPI my_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate)
{
    if (lpFileName) {
        char upper[512];
        strncpy(upper, lpFileName, sizeof(upper) - 1);
        upper[sizeof(upper) - 1] = '\0';
        _strupr(upper);
        if (strstr(upper, "VID_A466")) {
            const char *f = strstr(upper, "FAKE");
            if (f) {
                int idx = atoi(f + 4);
                if (idx >= 0 && idx < FAKE_MAX) {
                    dbg("CreateFileA: TEST fake device %d", idx);
                    return fake_handle(idx);
                }
            }
            {
                int i = enum_index_for_path(upper);
                if (i >= 0) {
                    dbg("CreateFileA: real device index %d", i);
                    return (HANDLE)(REAL_HANDLE_BASE | (ULONG_PTR)i);
                }
            }
            dbg("CreateFileA: unparsed XGecu path -> index 0");
            return (HANDLE)(REAL_HANDLE_BASE | 0);
        }
    }
    if (!orig_CreateFileA) {
        orig_CreateFileA = (pfn_CreateFileA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    }
    if (!orig_CreateFileA) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return INVALID_HANDLE_VALUE;
    }
    return orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreation, dwFlags, hTemplate);
}

typedef HANDLE (WINAPI *pfn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static pfn_CreateFileW orig_CreateFileW = NULL;

/* Xgpro 13.16 and 13.25 open the programmer with CreateFileA and use
 * CreateFileW only for ordinary files, so hooking the A variant is enough
 * today. Hook W as well - filtered on the device path, everything else falls
 * through - so an update that switches to the W variant cannot silently
 * bypass the shim and report "no programmer". */
static HANDLE WINAPI my_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate)
{
    if (lpFileName) {
        char ansi[1024];
        int n = WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, ansi, sizeof(ansi), NULL, NULL);

        if (n > 0) {
            _strupr(ansi);
            if (strstr(ansi, "VID_A466")) {
                const char *f = strstr(ansi, "FAKE");
                if (f) {
                    int idx = atoi(f + 4);
                    if (idx >= 0 && idx < FAKE_MAX) {
                        dbg("CreateFileW: TEST fake device %d", idx);
                        return fake_handle(idx);
                    }
                }
                {
                    int i = enum_index_for_path(ansi);
                    if (i >= 0) {
                        dbg("CreateFileW: real device index %d", i);
                        return (HANDLE)(REAL_HANDLE_BASE | (ULONG_PTR)i);
                    }
                }
                dbg("CreateFileW: unparsed XGecu path -> index 0");
                return (HANDLE)(REAL_HANDLE_BASE | 0);
            }
        }
    }
    if (!orig_CreateFileW)
        orig_CreateFileW = (pfn_CreateFileW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW");
    if (!orig_CreateFileW) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return INVALID_HANDLE_VALUE;
    }
    return orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreation, dwFlags, hTemplate);
}


static HINTERNET WINAPI my_InternetOpenA(
    LPCSTR lpszAgent, DWORD dwAccessType,
    LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
    if (is_verbose())
        dbg("InternetOpenA: stubbed");
    return (HINTERNET)(ULONG_PTR)0xDEAD0001;
}

static HINTERNET WINAPI my_InternetConnectA(
    HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService,
    DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("InternetConnectA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static HINTERNET WINAPI my_InternetOpenUrlA(
    HINTERNET hInternet, LPCSTR lpszUrl,
    LPCSTR lpszHeaders, DWORD dwHeadersLength,
    DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("InternetOpenUrlA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static HINTERNET WINAPI my_HttpOpenRequestA(
    HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName,
    LPCSTR lpszVersion, LPCSTR lpszReferrer,
    LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("HttpOpenRequestA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static BOOL WINAPI my_HttpSendRequestA(
    HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength)
{
    if (is_verbose())
        dbg("HttpSendRequestA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return FALSE;
}

static BOOL WINAPI my_InternetCloseHandle(HINTERNET hInternet)
{
    return TRUE;
}


static void patch_iat_entry(HMODULE module, const char *target_dll,
                            const char *func_name, void *new_func, void **orig_func)
{
    ULONG_PTR base = (ULONG_PTR)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (import_rva == 0 || import_size == 0)
        return;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + import_rva);

    for (; imp->Name; imp++) {
        const char *dll_name = (const char *)(base + imp->Name);
        if (_stricmp(dll_name, target_dll) != 0) continue;

        IMAGE_THUNK_DATA *orig_thunk = imp->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
            : (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA *iat_thunk  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        for (; orig_thunk->u1.AddressOfData; orig_thunk++, iat_thunk++) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *)(base + orig_thunk->u1.AddressOfData);
            if (strcmp((const char *)import->Name, func_name) != 0) continue;

            DWORD old_protect;
            VirtualProtect(&iat_thunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old_protect);

            if (orig_func) *orig_func = (void *)iat_thunk->u1.Function;
            iat_thunk->u1.Function = (ULONG_PTR)new_func;

            VirtualProtect(&iat_thunk->u1.Function, sizeof(ULONG_PTR), old_protect, &old_protect);
            return;
        }
    }
}

typedef HDEVNOTIFY (WINAPI *pfn_RegDevNotifA)(HANDLE, LPVOID, DWORD);
/* TEST-ONLY UI probe (XGPRO_DUMP_UI): dumps the app's own status bar and
 * list counts from inside the process, so the multi-device table can be
 * verified without a screenshot.  Off by default. */
#define SB_GETTEXT_A_MSG   (WM_USER + 2)
#define SB_GETPARTS_MSG    (WM_USER + 6)
#define LVM_GETITEMCOUNT_MSG 0x1004
#define TB_GETBUTTONTEXT_A_MSG (WM_USER + 75)

static LONG ui_dump_started = 0;

static BOOL CALLBACK ui_top_cb(HWND h, LPARAM l)
{
    char txt[256] = {0};
    GetWindowTextA(h, txt, sizeof(txt));
    if (strstr(txt, "Xgpro")) {
        *(HWND *)l = h;
        return FALSE;
    }
    return TRUE;
}

static BOOL CALLBACK ui_child_cb(HWND h, LPARAM l)
{
    char cls[128] = {0}, txt[512] = {0};
    GetClassNameA(h, cls, sizeof(cls));
    GetWindowTextA(h, txt, sizeof(txt));
    if (!strcmp(cls, "msctls_statusbar32")) {
        int parts = (int)SendMessageA(h, SB_GETPARTS_MSG, 0, 0);
        dbg("UI DUMP: status bar parts=%d", parts);
        for (int i = 0; i < parts; i++) {
            char b[512] = {0};
            SendMessageA(h, SB_GETTEXT_A_MSG, (WPARAM)i, (LPARAM)b);
            dbg("UI DUMP: status[%d]=\"%s\"", i, b);
        }
    } else if (!strcmp(cls, "Static")) {
        if (strstr(txt, "rogrammer"))
            dbg("UI DUMP: static=\"%s\"", txt);
    } else if (!strcmp(cls, "SysListView32")) {
        dbg("UI DUMP: list \"%s\" count=%ld", txt,
            (long)SendMessageA(h, LVM_GETITEMCOUNT_MSG, 0, 0));
    } else if (!strcmp(cls, "ToolbarWindow32")) {
        for (int id = 1; id < 200; id++) {
            char b[256] = {0};
            if (SendMessageA(h, TB_GETBUTTONTEXT_A_MSG, (WPARAM)id,
                             (LPARAM)b) > 0)
                dbg("UI DUMP: toolbar id=%d text=\"%s\"", id, b);
        }
    }
    return TRUE;
}

static DWORD WINAPI ui_dump_thread(LPVOID p)
{
    (void)p;
    Sleep(8000);
    HWND top = NULL;
    EnumWindows(ui_top_cb, (LPARAM)&top);
    if (!top) {
        dbg("UI DUMP: Xgpro window not found");
        return 0;
    }
    dbg("UI DUMP: top=%p", (void *)top);
    EnumChildWindows(top, ui_child_cb, 0);
    return 0;
}

static pfn_RegDevNotifA orig_RegisterDeviceNotificationA = NULL;
static DWORD WINAPI subscriber_thread(LPVOID unused);

/* Xgpro registers for device-interface notifications and then waits for a
 * DBT_DEVICEREMOVECOMPLETE/DBT_DEVICEARRIVAL pair as the "USB port reset ack"
 * after asking the programmer to reset its port (command 0x3F). Nothing
 * arrives under Wine, so remember the window and replay the pair ourselves. */
static HDEVNOTIFY WINAPI my_RegisterDeviceNotificationA(
    HANDLE hRecipient, LPVOID NotificationFilter, DWORD Flags)
{
    if (NotificationFilter) {
        const BYTE *p = (const BYTE *)NotificationFilter;
        if (*(DWORD *)(p + 4) == DBT_DEVTYP_DEVICEINTERFACE) {
            memcpy(&notify_guid, p + 12, sizeof(GUID));
            notify_guid_valid = TRUE;
        }
    }
    notify_hwnd = (HWND)hRecipient;
    dbg("RegisterDeviceNotificationA: hwnd=%p guid_valid=%d",
        (void *)notify_hwnd, notify_guid_valid);

    if (InterlockedExchange(&sub_started, 1) == 0) {
        CloseHandle(CreateThread(NULL, 0, subscriber_thread, NULL, 0, NULL));
        dbg("started hotplug subscriber");
    }
    if (getenv("XGPRO_DUMP_UI") &&
        InterlockedExchange(&ui_dump_started, 1) == 0) {
        CloseHandle(CreateThread(NULL, 0, ui_dump_thread, NULL, 0, NULL));
        dbg("started UI dump");
    }
    return (HDEVNOTIFY)(ULONG_PTR)0xDB000001;
}


/* Subscribe to the daemon's libusb hotplug feed and replay the real
 * attach/detach events to the window the app registered. Nothing is
 * synthesised: the app only hears about what the hardware actually did. */
static DWORD WINAPI subscriber_thread(LPVOID unused)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in a;
    uint8_t token[BRIDGE_TOKEN_LEN];
    DWORD got = 0;
    HANDLE h;
    bridge_request_t req;

    (void)unused;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(BRIDGE_PORT);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(s); return 0; }

    h = CreateFileA(BRIDGE_TOKEN_PATH_WINE, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { closesocket(s); return 0; }
    if (!ReadFile(h, token, BRIDGE_TOKEN_LEN, &got, NULL) || got != BRIDGE_TOKEN_LEN) {
        CloseHandle(h);
        closesocket(s);
        return 0;
    }
    CloseHandle(h);
    if (send(s, (const char *)token, BRIDGE_TOKEN_LEN, 0) != BRIDGE_TOKEN_LEN) {
        closesocket(s);
        return 0;
    }

    if (bridge_hello_sock(s, (selected_profile >= 0) ?
                              XGPRO_MODELS[selected_profile].pid : 0) < 0) {
        closesocket(s);
        return 0;
    }

    ZeroMemory(&req, sizeof(req));
    req.cmd = CMD_SUBSCRIBE;
    if (send(s, (const char *)&req, sizeof(req), 0) != sizeof(req)) {
        closesocket(s);
        return 0;
    }
    dbg("hotplug subscriber connected");

    for (;;) {
        bridge_event_t ev;
        DEV_BROADCAST_DEVICEINTERFACE_W bi;

        if (sock_recv_all(s, &ev, sizeof(ev)) < 0) break;

        ZeroMemory(&bi, sizeof(bi));
        bi.dbcc_size = sizeof(bi);
        bi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        if (notify_guid_valid) bi.dbcc_classguid = notify_guid;

        InterlockedExchange(&enum_valid, 0);
        dbg("hardware event: %s pid=%04x", ev.evt ? "arrived" : "removed", ev.pid);
        if (notify_hwnd) {
            SendMessageW(notify_hwnd, WM_DEVICECHANGE,
                         ev.evt ? DBT_DEVICEARRIVAL : DBT_DEVICEREMOVECOMPLETE,
                         (LPARAM)&bi);
            RedrawWindow(notify_hwnd, NULL, NULL, RDW_INVALIDATE);
        }
    }

    dbg("hotplug subscriber disconnected");
    closesocket(s);
    return 0;
}

static void install_hooks(void) {
    HMODULE exe = GetModuleHandleA(NULL);

    orig_CreateFileA = (pfn_CreateFileA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");

    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiGetClassDevsA",
                    my_SetupDiGetClassDevsA, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiEnumDeviceInterfaces",
                    my_SetupDiEnumDeviceInterfaces, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiGetDeviceInterfaceDetailA",
                    my_SetupDiGetDeviceInterfaceDetailA, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiDestroyDeviceInfoList",
                    my_SetupDiDestroyDeviceInfoList, NULL);

    patch_iat_entry(exe, "KERNEL32.dll", "CreateFileA",
                    my_CreateFileA, (void **)&orig_CreateFileA);
    patch_iat_entry(exe, "KERNEL32.dll", "CreateFileW",
                    my_CreateFileW, (void **)&orig_CreateFileW);

    patch_iat_entry(exe, "USER32.dll", "RegisterDeviceNotificationA",
                    my_RegisterDeviceNotificationA,
                    (void **)&orig_RegisterDeviceNotificationA);

    patch_iat_entry(exe, "WININET.dll", "InternetOpenA",
                    my_InternetOpenA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetConnectA",
                    my_InternetConnectA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetOpenUrlA",
                    my_InternetOpenUrlA, NULL);
    patch_iat_entry(exe, "WININET.dll", "HttpOpenRequestA",
                    my_HttpOpenRequestA, NULL);
    patch_iat_entry(exe, "WININET.dll", "HttpSendRequestA",
                    my_HttpSendRequestA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetCloseHandle",
                    my_InternetCloseHandle, NULL);
}


__declspec(dllexport) BOOL __stdcall WinUsb_Initialize(
    HANDLE DeviceHandle, void **InterfaceHandle)
{
    int fi = fake_index_from_handle(DeviceHandle);
    int ri = real_index_from_handle(DeviceHandle);
    bridge_conn_t *c;
    uint16_t pid = (selected_profile >= 0) ? XGPRO_MODELS[selected_profile].pid : 0;
    const char *path = "";

    dbg("WinUsb_Initialize");
    if (!InterfaceHandle) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    c = (bridge_conn_t *)calloc(1, sizeof(*c));
    if (!c) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    c->sock = INVALID_SOCKET;
    c->fake = -1;

    if (fi >= 0) {
        dbg("  -> TEST fake device %d", fi);
        c->fake = fi;
        c->index = fi;
        *InterfaceHandle = c;
        return TRUE;
    }

    if (!enum_valid) {
        EnterCriticalSection(&bridge_cs);
        if (!enum_valid) bridge_enumerate();
        LeaveCriticalSection(&bridge_cs);
    }

    if (ri < 0) ri = 0;
    if (ri < (int)enum_count) {
        if (enum_devs[ri].fake >= 0) {
            dbg("  -> TEST fake device %d (enumerated)", enum_devs[ri].fake);
            c->fake = enum_devs[ri].fake;
            c->index = ri;
            *InterfaceHandle = c;
            return TRUE;
        }
        path = enum_devs[ri].path;
        pid = enum_devs[ri].pid;
        c->index = ri;
        snprintf(c->path, sizeof(c->path), "%s", path);
    } else if (enum_count > 0) {
        dbg("  -> handle index %d has no enumerated device", ri);
        free(c);
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        return FALSE;
    }

    EnterCriticalSection(&bridge_cs);
    c->sock = bridge_open_session(path, pid);
    LeaveCriticalSection(&bridge_cs);
    if (c->sock == INVALID_SOCKET) {
        dbg("  -> bridge open failed for %s", path[0] ? path : "(first match)");
        free(c);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    dbg("  -> opened %s", path[0] ? path : "(first match)");
    *InterfaceHandle = c;
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_Free(void *InterfaceHandle) {
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    dbg("WinUsb_Free");
    if (!c)
        return TRUE;
    EnterCriticalSection(&bridge_cs);
    bridge_close_session(c);
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

/* Xgpro drives payload transfers as OVERLAPPED I/O: it creates an event,
 * passes it to WinUsb_ReadPipe/WritePipe and then waits on it. Our transfers
 * are synchronous, so the work is already done when the call returns - but
 * the event still has to be set, otherwise the app waits until its own
 * timeout and reports "read timeout at address 0" even though the data
 * arrived. */
static void complete_overlapped(void *Overlapped, BOOL ok, DWORD transferred)
{
    LPOVERLAPPED ov = (LPOVERLAPPED)Overlapped;
    if (!ov) return;
    ov->Internal = ok ? 0 : (ULONG_PTR)GetLastError();
    ov->InternalHigh = ok ? transferred : 0;
    if (ov->hEvent) SetEvent(ov->hEvent);
}

static BOOL write_pipe(bridge_conn_t *c, UCHAR PipeID, PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    if (is_verbose()) {
        char hex[128] = {0};
        ULONG i, off = 0;
        for (i = 0; i < BufferLength && i < 32 && off < sizeof(hex) - 4; i++)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x ", Buffer ? Buffer[i] : 0);
        dbg("WinUsb_WritePipe pipe=0x%02x len=%u data=%s", PipeID, BufferLength, hex);
    }

    EnterCriticalSection(&bridge_cs);
    if (!c || c->sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_WRITE_PIPE, PipeID, BufferLength, pipe_timeout_ms[PipeID] };
    if (sock_send_all(c->sock, &req, sizeof(req)) < 0) {
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    if (BufferLength > 0 && sock_send_all(c->sock, Buffer, BufferLength) < 0) {
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (sock_recv_all(c->sock, &resp, sizeof(resp)) < 0) {
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    LeaveCriticalSection(&bridge_cs);

    if (LengthTransferred) *LengthTransferred = resp.length;
    if (resp.status != 0) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

static BOOL read_pipe(bridge_conn_t *c, UCHAR PipeID, PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    if (is_verbose())
        dbg("WinUsb_ReadPipe pipe=0x%02x len=%u", PipeID, BufferLength);

    EnterCriticalSection(&bridge_cs);
    if (!c || c->sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_READ_PIPE, PipeID, BufferLength, pipe_timeout_ms[PipeID] };
    if (sock_send_all(c->sock, &req, sizeof(req)) < 0) {
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (sock_recv_all(c->sock, &resp, sizeof(resp)) < 0) {
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    if (resp.length > MAX_TRANSFER_LEN) {
        dbg("WinUsb_ReadPipe: resp.length %u exceeds max, disconnecting", resp.length);
        session_drop(c);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    uint32_t total_from_daemon = resp.length;
    if (resp.length > BufferLength) {
        dbg("WARNING: daemon sent %u bytes but buffer only holds %u", total_from_daemon, BufferLength);
        resp.length = BufferLength;
    }

    if (resp.length > 0 && Buffer) {
        if (sock_recv_all(c->sock, Buffer, resp.length) < 0) {
            session_drop(c);
            LeaveCriticalSection(&bridge_cs);
            SetLastError(ERROR_GEN_FAILURE);
            return FALSE;
        }
    }

    if (is_verbose() && resp.length > 0 && Buffer) {
        char hex[256] = {0};
        ULONG i, off = 0;
        for (i = 0; i < resp.length && i < 64 && off < sizeof(hex) - 4; i++)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x ", Buffer[i]);
        dbg("WinUsb_ReadPipe pipe=0x%02x got=%u data=%s", PipeID, resp.length, hex);
    }

    if (total_from_daemon > resp.length) {
        uint32_t remain = total_from_daemon - resp.length;
        char discard[4096];
        while (remain > 0) {
            uint32_t chunk = remain < sizeof(discard) ? remain : sizeof(discard);
            if (sock_recv_all(c->sock, discard, chunk) < 0) {
                session_drop(c);
                LeaveCriticalSection(&bridge_cs);
                SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
            remain -= chunk;
        }
    }
    LeaveCriticalSection(&bridge_cs);

    if (LengthTransferred) *LengthTransferred = resp.length;
    if (resp.status != 0) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_WritePipe(
    void *InterfaceHandle, UCHAR PipeID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred, void *Overlapped)
{
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    BOOL ok = (c && c->fake >= 0) ?
        fake_write_pipe(c->fake, PipeID, Buffer, BufferLength, LengthTransferred) :
        write_pipe(c, PipeID, Buffer, BufferLength, LengthTransferred);
    complete_overlapped(Overlapped, ok, (ok && LengthTransferred) ? *LengthTransferred : 0);
    return ok;
}

__declspec(dllexport) BOOL __stdcall WinUsb_ReadPipe(
    void *InterfaceHandle, UCHAR PipeID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred, void *Overlapped)
{
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    BOOL ok = (c && c->fake >= 0) ?
        fake_read_pipe(c->fake, PipeID, Buffer, BufferLength, LengthTransferred) :
        read_pipe(c, PipeID, Buffer, BufferLength, LengthTransferred);
    complete_overlapped(Overlapped, ok, (ok && LengthTransferred) ? *LengthTransferred : 0);
    return ok;
}

__declspec(dllexport) BOOL __stdcall WinUsb_SetPipePolicy(
    void *InterfaceHandle, UCHAR PipeID, ULONG PolicyType, ULONG ValueLength, void *Value)
{
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    if (!c || c->fake >= 0)
        return TRUE;
    if (is_verbose())
        dbg("WinUsb_SetPipePolicy pipe=0x%02x policy=%u", PipeID, PolicyType);

    /* PIPE_TRANSFER_TIMEOUT: the app expects a transfer against a
     * disappeared device to fail after this timeout, not hang. */
    if (PolicyType == 3 && Value && ValueLength >= sizeof(DWORD)) {
        pipe_timeout_ms[PipeID] = *(DWORD *)Value;
        if (is_verbose())
            dbg("  pipe 0x%02x timeout = %u ms", PipeID, pipe_timeout_ms[PipeID]);
    }

    EnterCriticalSection(&bridge_cs);
    if (c->sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_SET_PIPE_POLICY, PipeID, PolicyType };
        if (sock_send_all(c->sock, &req, sizeof(req)) == 0) {
            bridge_response_t resp;
            sock_recv_all(c->sock, &resp, sizeof(resp));
        }
    }
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_FlushPipe(void *InterfaceHandle, UCHAR PipeID) {
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    if (!c || c->fake >= 0)
        return TRUE;
    if (is_verbose())
        dbg("WinUsb_FlushPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (c->sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_FLUSH_PIPE, PipeID, 0 };
        if (sock_send_all(c->sock, &req, sizeof(req)) == 0) {
            bridge_response_t resp;
            sock_recv_all(c->sock, &resp, sizeof(resp));
        }
    }
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_AbortPipe(void *InterfaceHandle, UCHAR PipeID) {
    bridge_conn_t *c = (bridge_conn_t *)InterfaceHandle;
    if (!c || c->fake >= 0)
        return TRUE;
    if (is_verbose())
        dbg("WinUsb_AbortPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (c->sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_ABORT_PIPE, PipeID, 0 };
        if (sock_send_all(c->sock, &req, sizeof(req)) == 0) {
            bridge_response_t resp;
            sock_recv_all(c->sock, &resp, sizeof(resp));
        }
    }
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

typedef struct {
    UCHAR bLength;
    UCHAR bDescriptorType;
    UCHAR bInterfaceNumber;
    UCHAR bAlternateSetting;
    UCHAR bNumEndpoints;
    UCHAR bInterfaceClass;
    UCHAR bInterfaceSubClass;
    UCHAR bInterfaceProtocol;
    UCHAR iInterface;
} USB_INTERFACE_DESCRIPTOR;

typedef struct {
    ULONG PipeType;
    UCHAR PipeId;
    USHORT MaximumPacketSize;
    UCHAR Interval;
} WINUSB_PIPE_INFORMATION;

__declspec(dllexport) BOOL __stdcall WinUsb_QueryInterfaceSettings(
    void *InterfaceHandle, UCHAR AlternateInterfaceNumber, USB_INTERFACE_DESCRIPTOR *desc)
{
    dbg("WinUsb_QueryInterfaceSettings alt=%u", AlternateInterfaceNumber);
    if (AlternateInterfaceNumber != 0 || !desc) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
    desc->bLength = 9;
    desc->bDescriptorType = 4;
    desc->bInterfaceNumber = 0;
    desc->bAlternateSetting = 0;
    desc->bNumEndpoints = 4;
    desc->bInterfaceClass = 0xFF;
    desc->bInterfaceSubClass = 0xFF;
    desc->bInterfaceProtocol = 0xFF;
    desc->iInterface = 0;
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_QueryPipe(
    void *InterfaceHandle, UCHAR AlternateInterfaceNumber, UCHAR PipeIndex,
    WINUSB_PIPE_INFORMATION *PipeInfo)
{
    dbg("WinUsb_QueryPipe alt=%u index=%u", AlternateInterfaceNumber, PipeIndex);
    if (!PipeInfo || AlternateInterfaceNumber != 0) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
    switch (PipeIndex) {
    case 0:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x01;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 1:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x81;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 2:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x02;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 3:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x82;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    default:
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
}

__declspec(dllexport) BOOL __stdcall WinUsb_QueryDeviceInformation(
    void *InterfaceHandle, ULONG InformationType, PULONG BufferLength, void *Buffer)
{
    dbg("WinUsb_QueryDeviceInformation type=%u", InformationType);
    if (InformationType == 1 && Buffer && BufferLength && *BufferLength >= 1) {
        *(UCHAR *)Buffer = 3;
        *BufferLength = 1;
        return TRUE;
    }
    return FALSE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_GetDescriptor(
    void *h, UCHAR DescriptorType, UCHAR Index, USHORT LanguageID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    dbg("WinUsb_GetDescriptor type=%u index=%u lang=%u", DescriptorType, Index, LanguageID);
    SetLastError(ERROR_GEN_FAILURE);
    return FALSE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_ControlTransfer(void *h, void *sp, UCHAR *buf, ULONG len, PULONG xfer, void *ol)
{
    const UCHAR *setup = (const UCHAR *)sp;
    dbg("WinUsb_ControlTransfer: unsupported (bmRequestType=0x%02x bRequest=0x%02x len=%lu)",
        setup ? setup[0] : 0, setup ? setup[1] : 0, (unsigned long)len);
    SetLastError(ERROR_NOT_SUPPORTED);
    if (xfer) *xfer = 0;
    return FALSE;
}
__declspec(dllexport) BOOL __stdcall WinUsb_GetAssociatedInterface(void *h, UCHAR idx, void **ah) { dbg("WinUsb_GetAssociatedInterface idx=%u", idx); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetCurrentAlternateSetting(void *h, PUCHAR alt) { dbg("WinUsb_GetCurrentAlternateSetting"); if (alt) *alt = 0; return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetOverlappedResult(void *h, void *ol, PULONG xfer, BOOL wait) { dbg("WinUsb_GetOverlappedResult (stub)"); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetPipePolicy(void *h, UCHAR pid, ULONG pt, PULONG vl, void *v) { dbg("WinUsb_GetPipePolicy pipe=0x%02x policy=%u", pid, pt); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetPowerPolicy(void *h, ULONG pt, PULONG vl, void *v) { dbg("WinUsb_GetPowerPolicy (stub)"); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_ResetPipe(void *h, UCHAR pid) { dbg("WinUsb_ResetPipe pipe=0x%02x", pid); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_SetCurrentAlternateSetting(void *h, UCHAR alt) { dbg("WinUsb_SetCurrentAlternateSetting alt=%u", alt); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_SetPowerPolicy(void *h, ULONG pt, ULONG vl, void *v) { dbg("WinUsb_SetPowerPolicy (stub)"); return FALSE; }

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&bridge_cs);
        install_hooks();
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&bridge_cs);
    }
    return TRUE;
}
