#ifndef BRIDGE_PROTO_H
#define BRIDGE_PROTO_H

#include <stdint.h>

#define BRIDGE_PORT 7372
#define BRIDGE_PATH_LEN 64
/* Xgpro/Minipro have four programmer slots; Xgpro_T76 has one, which
 * the shim enforces separately. */
#define BRIDGE_MAX_DEVICES 4

/* Bumped whenever bridge_request_t/bridge_hello_t or the command semantics
 * change. The shim sends CMD_HELLO right after auth; a daemon that rejects it
 * (old version, unknown command) reports a clean mismatch instead of
 * misparsing the next transfer. */
#define BRIDGE_PROTO_VERSION 3u

enum bridge_cmd {
    CMD_OPEN = 1,
    CMD_CLOSE,
    CMD_READ_PIPE,
    CMD_WRITE_PIPE,
    CMD_SET_PIPE_POLICY,
    CMD_FLUSH_PIPE,
    CMD_ABORT_PIPE,
    CMD_SUBSCRIBE,
    CMD_HELLO,
    CMD_ENUMERATE,
};

/* Sent immediately after the auth token, before CMD_OPEN. */
typedef struct {
    uint16_t version;   /* BRIDGE_PROTO_VERSION */
    uint16_t pid;       /* requested programmer PID, 0 = any */
} bridge_hello_t;

/* CMD_OPEN body: daemon-side device path ("bus:addr"); empty = first match. */
typedef struct {
    char path[BRIDGE_PATH_LEN];
} bridge_open_t;

/* Pushed to a subscriber when a programmer genuinely attaches/detaches. */
typedef struct {
    uint8_t  evt;    /* 1 = arrived, 0 = removed */
    uint16_t pid;
    uint8_t  bus;
    uint8_t  addr;
} bridge_event_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t cmd;
    uint8_t pipe_id;
    uint32_t length;
    uint32_t timeout_ms;   /* 0 = use the daemon default */
} bridge_request_t;

typedef struct {
    int32_t status;
    uint32_t length;
} bridge_response_t;

/* One entry in the CMD_ENUMERATE payload.  The payload starts with a u32
 * count, then this struct repeated `count` times. */
typedef struct {
    uint16_t vid;
    uint16_t pid;
    uint8_t  bus;
    uint8_t  addr;
    char     path[BRIDGE_PATH_LEN];
    char     product[64];
} bridge_dev_info_t;
#pragma pack(pop)

/* All XGecu programmers share the same vendor ID; PIDs, GUIDs and endpoint
 * layouts live in xgpro_models.h. */
#define XGPRO_VID      0xA466

/* Bulk endpoint addresses are discovered from the device descriptor, because
 * they are not guaranteed to be identical across programmer models. */

#define BRIDGE_TOKEN_LEN 32
#define BRIDGE_TOKEN_PATH "/tmp/.xgpro-bridge-token"

#endif
