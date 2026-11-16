#ifndef BRIDGE_PROTO_H
#define BRIDGE_PROTO_H

#include <stdint.h>

#define BRIDGE_PORT 7372

/* Bumped whenever bridge_request_t/bridge_hello_t or the command semantics
 * change. The shim sends CMD_HELLO right after auth; a daemon that rejects it
 * (old version, unknown command) reports a clean mismatch instead of
 * misparsing the next transfer. */
#define BRIDGE_PROTO_VERSION 2u

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
};

/* Sent immediately after the auth token, before CMD_OPEN. */
typedef struct {
    uint16_t version;   /* BRIDGE_PROTO_VERSION */
    uint16_t pid;       /* requested programmer PID, 0 = any */
} bridge_hello_t;

/* Pushed to a subscriber when the programmer genuinely attaches/detaches. */
typedef struct {
    uint8_t  evt;    /* 1 = arrived, 0 = removed */
    uint16_t pid;
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
#pragma pack(pop)

/* All XGecu programmers share the same vendor ID; PIDs, GUIDs and endpoint
 * layouts live in xgpro_models.h. */
#define XGPRO_VID      0xA466

/* Bulk endpoint addresses are discovered from the device descriptor, because
 * they are not guaranteed to be identical across programmer models. */

#define BRIDGE_TOKEN_LEN 32
#define BRIDGE_TOKEN_PATH "/tmp/.xgpro-bridge-token"

#endif
