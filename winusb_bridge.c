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
static char fake_dev_path[260];

#define FAKE_HDEVINFO       ((HANDLE)(ULONG_PTR)0xDE000001)
#define FAKE_FILE_HANDLE    ((HANDLE)(ULONG_PTR)0xCA000001)
#define FAKE_WINUSB_HANDLE  ((void *)(ULONG_PTR)0xBE000001)

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

static const char *device_path(void) {
    const xgpro_model_t *p = current_profile();
    const xgpro_guid_t *g = &p->guid;

    snprintf(fake_dev_path, sizeof(fake_dev_path),
             "\\\\?\\USB#VID_A466&PID_%04X#%s#{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             p->pid, p->name,
             (unsigned long)g->d1, g->d2, g->d3,
             g->d4[0], g->d4[1], g->d4[2], g->d4[3],
             g->d4[4], g->d4[5], g->d4[6], g->d4[7]);
    return fake_dev_path;
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

static SOCKET bridge_sock = INVALID_SOCKET;
static int wsa_inited = 0;
static CRITICAL_SECTION bridge_cs;
static int debug_verbose = -1;

static void bridge_disconnect(void) {
    if (bridge_sock != INVALID_SOCKET) {
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
    }
}

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


static int bridge_send(const void *buf, int len);
static int bridge_recv(void *buf, int len);

static int bridge_connect(void) {
    if (bridge_sock != INVALID_SOCKET) return 0;

    if (!wsa_inited) {
        WSADATA wsa;
        int err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (err != 0) {
            dbg("WSAStartup failed: %d", err);
            return -1;
        }
        wsa_inited = 1;
    }

    bridge_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bridge_sock == INVALID_SOCKET) {
        dbg("socket failed: %d", WSAGetLastError());
        return -1;
    }

    {
        int flag = 1;
        setsockopt(bridge_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
    }

    {
        int bufsize = 256 * 1024;
        setsockopt(bridge_sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));
        setsockopt(bridge_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BRIDGE_PORT);
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */

    if (connect(bridge_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        dbg("connect to bridge failed: %d", WSAGetLastError());
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
        return -1;
    }

    dbg("Connected to bridge daemon on port %d", BRIDGE_PORT);

    {
        HANDLE hFile = CreateFileA(BRIDGE_TOKEN_PATH_WINE, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            dbg("Failed to open token file: %s (err=%d)", BRIDGE_TOKEN_PATH_WINE, (int)GetLastError());
            closesocket(bridge_sock);
            bridge_sock = INVALID_SOCKET;
            return -1;
        }
        uint8_t token[BRIDGE_TOKEN_LEN];
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(hFile, token, BRIDGE_TOKEN_LEN, &bytes_read, NULL);
        CloseHandle(hFile);
        if (!ok || bytes_read != BRIDGE_TOKEN_LEN) {
            dbg("Failed to read token file (read %u bytes)", (unsigned)bytes_read);
            closesocket(bridge_sock);
            bridge_sock = INVALID_SOCKET;
            return -1;
        }
        if (bridge_send(token, BRIDGE_TOKEN_LEN) < 0) {
            dbg("Failed to send auth token");
            bridge_disconnect();
            return -1;
        }
        dbg("Auth token sent to bridge daemon");
    }

    {
        bridge_request_t hreq = { CMD_HELLO, 0, 0 };
        bridge_hello_t hello;
        bridge_response_t resp = { 0, 0 };
        hello.version = BRIDGE_PROTO_VERSION;
        hello.pid = (selected_profile >= 0) ? XGPRO_MODELS[selected_profile].pid : 0;
        if (bridge_send(&hreq, sizeof(hreq)) < 0 ||
            bridge_send(&hello, sizeof(hello)) < 0 ||
            bridge_recv(&resp, sizeof(resp)) < 0 || resp.status != 0) {
            dbg("Bridge rejected protocol v%u / PID %04x (status %d, daemon v%u)",
                hello.version, hello.pid, resp.status, resp.length);
            bridge_disconnect();
            SetLastError(ERROR_REVISION_MISMATCH);
            return -1;
        }
        dbg("Bridge protocol v%u, requested PID %04x", hello.version, hello.pid);
    }

    return 0;
}

static int bridge_send(const void *buf, int len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        int n = send(bridge_sock, p, len, 0);
        if (n <= 0) { bridge_disconnect(); return -1; }
        p += n;
        len -= n;
    }
    return 0;
}

static int bridge_recv(void *buf, int len) {
    char *p = (char *)buf;
    while (len > 0) {
        int n = recv(bridge_sock, p, len, 0);
        if (n <= 0) { bridge_disconnect(); return -1; }
        p += n;
        len -= n;
    }
    return 0;
}


static HANDLE WINAPI my_SetupDiGetClassDevsA(
    const GUID *ClassGuid, const char *Enumerator, HWND hwndParent, DWORD Flags)
{
    if (ClassGuid) {
        int idx = profile_index_for_guid(ClassGuid);
        if (idx >= 0) {
            selected_profile = idx;
            dbg("SetupDiGetClassDevsA: matched %s GUID -> returning fake HDEVINFO",
                XGPRO_MODELS[idx].name);
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
        MemberIndex < (DWORD)fake_total()) {
        dbg("SetupDiEnumDeviceInterfaces: returning %s at index %lu",
            MemberIndex == 0 ? current_profile()->name : "FAKE",
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
    const char *path = (idx == 0) ? device_path() : fake_device_path((int)idx);
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
            dbg("CreateFileA: intercepted XGecu device open -> fake handle");
            return FAKE_FILE_HANDLE;
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
                dbg("CreateFileW: intercepted XGecu device open -> fake handle");
                return FAKE_FILE_HANDLE;
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

static int sub_recv_all(SOCKET s, void *buf, int len)
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

        if (sub_recv_all(s, &ev, sizeof(ev)) < 0) break;

        ZeroMemory(&bi, sizeof(bi));
        bi.dbcc_size = sizeof(bi);
        bi.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        if (notify_guid_valid) bi.dbcc_classguid = notify_guid;

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
    dbg("WinUsb_Initialize");

    {
        int fi = fake_index_from_handle(DeviceHandle);
        if (fi >= 0) {
            dbg("  -> TEST fake device %d", fi);
            if (InterfaceHandle) *InterfaceHandle = DeviceHandle;
            return TRUE;
        }
    }

    EnterCriticalSection(&bridge_cs);
    if (bridge_connect() < 0) {
        dbg("  -> failed to connect to bridge");
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_OPEN, 0, 0 };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0 || resp.status != 0) {
        dbg("  -> bridge open failed: %d", resp.status);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    LeaveCriticalSection(&bridge_cs);

    if (InterfaceHandle) *InterfaceHandle = FAKE_WINUSB_HANDLE;
    dbg("  -> success");
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_Free(void *InterfaceHandle) {
    dbg("WinUsb_Free");
    if (fake_index_from_handle((HANDLE)InterfaceHandle) >= 0)
        return TRUE;
    EnterCriticalSection(&bridge_cs);
    if (bridge_sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_CLOSE, 0, 0 };
        bridge_send(&req, sizeof(req));
        bridge_response_t resp;
        bridge_recv(&resp, sizeof(resp));
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
    }
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

static BOOL write_pipe(UCHAR PipeID, PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    if (is_verbose()) {
        char hex[128] = {0};
        ULONG i, off = 0;
        for (i = 0; i < BufferLength && i < 32 && off < sizeof(hex) - 4; i++)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x ", Buffer ? Buffer[i] : 0);
        dbg("WinUsb_WritePipe pipe=0x%02x len=%u data=%s", PipeID, BufferLength, hex);
    }

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_WRITE_PIPE, PipeID, BufferLength, pipe_timeout_ms[PipeID] };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    if (BufferLength > 0 && bridge_send(Buffer, BufferLength) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    LeaveCriticalSection(&bridge_cs);

    if (LengthTransferred) *LengthTransferred = resp.length;
    if (resp.status != 0) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

static BOOL read_pipe(UCHAR PipeID, PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    if (is_verbose())
        dbg("WinUsb_ReadPipe pipe=0x%02x len=%u", PipeID, BufferLength);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_READ_PIPE, PipeID, BufferLength, pipe_timeout_ms[PipeID] };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    if (resp.length > MAX_TRANSFER_LEN) {
        dbg("WinUsb_ReadPipe: resp.length %u exceeds max, disconnecting", resp.length);
        bridge_disconnect();
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
        if (bridge_recv(Buffer, resp.length) < 0) {
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
            if (bridge_recv(discard, chunk) < 0) {
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
    int fi = fake_index_from_handle((HANDLE)InterfaceHandle);
    BOOL ok = (fi >= 0) ?
        fake_write_pipe(fi, PipeID, Buffer, BufferLength, LengthTransferred) :
        write_pipe(PipeID, Buffer, BufferLength, LengthTransferred);
    complete_overlapped(Overlapped, ok, (ok && LengthTransferred) ? *LengthTransferred : 0);
    return ok;
}

__declspec(dllexport) BOOL __stdcall WinUsb_ReadPipe(
    void *InterfaceHandle, UCHAR PipeID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred, void *Overlapped)
{
    int fi = fake_index_from_handle((HANDLE)InterfaceHandle);
    BOOL ok = (fi >= 0) ?
        fake_read_pipe(fi, PipeID, Buffer, BufferLength, LengthTransferred) :
        read_pipe(PipeID, Buffer, BufferLength, LengthTransferred);
    complete_overlapped(Overlapped, ok, (ok && LengthTransferred) ? *LengthTransferred : 0);
    return ok;
}

__declspec(dllexport) BOOL __stdcall WinUsb_SetPipePolicy(
    void *InterfaceHandle, UCHAR PipeID, ULONG PolicyType, ULONG ValueLength, void *Value)
{
    if (fake_index_from_handle((HANDLE)InterfaceHandle) >= 0)
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
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_SET_PIPE_POLICY, PipeID, PolicyType };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_FlushPipe(void *InterfaceHandle, UCHAR PipeID) {
    if (fake_index_from_handle((HANDLE)InterfaceHandle) >= 0)
        return TRUE;
    if (is_verbose())
        dbg("WinUsb_FlushPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_FLUSH_PIPE, PipeID, 0 };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_AbortPipe(void *InterfaceHandle, UCHAR PipeID) {
    if (fake_index_from_handle((HANDLE)InterfaceHandle) >= 0)
        return TRUE;
    if (is_verbose())
        dbg("WinUsb_AbortPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_ABORT_PIPE, PipeID, 0 };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
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
