/*
 * xgpro_models.h - single source of truth for programmer-family differences.
 *
 * Included by both the Windows WinUSB shim (winusb_bridge.c) and the Linux
 * daemon (bridge_daemon.c).  Adding a new XGecu programmer is one row in
 * XGPRO_MODEL_TABLE(): identity (PID/GUID), payload endpoints, the endpoint
 * the firmware never services, the command that needs a pre-read drain, the
 * post-enumeration settle time and feature flags.
 */
#ifndef XGPRO_MODELS_H
#define XGPRO_MODELS_H

#include <stdint.h>
#include <stddef.h>

/* 16 bytes, layout-compatible with the Windows GUID type:
 *   uint32 Data1; uint16 Data2; uint16 Data3; uint8 Data4[8];
 * The shim memcpy()s this into a GUID; the daemon ignores it. */
typedef struct {
    uint32_t d1;
    uint16_t d2;
    uint16_t d3;
    uint8_t  d4[8];
} xgpro_guid_t;

typedef char xgpro_guid_must_be_16_bytes[(sizeof(xgpro_guid_t) == 16) ? 1 : -1];

/* Feature flags. */
#define XGPRO_F_DRAIN_BEFORE_READ (1u << 0)
#define XGPRO_F_DUAL_PAYLOAD      (1u << 1)

typedef struct {
    uint16_t     pid;
    const char  *name;
    xgpro_guid_t guid;

    /* Payload endpoints.  ep_*_peer is 0 for single-endpoint families. */
    uint8_t      ep_in;
    uint8_t      ep_in_peer;
    uint8_t      ep_out;
    uint8_t      ep_out_peer;

    /* Endpoint the firmware never services; reads there get a zero-length
     * success instead of burning the app's timeout.  0 = none. */
    uint8_t      unused_in_ep;

    /* Command opcode on the command pipe that must be preceded by draining
     * any queued payload from ep_in.  0 = never. */
    uint8_t      drain_on_opcode;

    uint16_t     settle_ms;
    uint32_t     flags;
} xgpro_model_t;

#define XGPRO_GUID_T48 \
    { 0xE7E8BA13, 0x2A81, 0x446E, \
      { 0xA1, 0x1E, 0x72, 0x39, 0x8F, 0xBD, 0xA8, 0x2F } }
#define XGPRO_GUID_T76 \
    { 0x015DE341, 0x91CC, 0x8286, \
      { 0x39, 0x64, 0x1A, 0x00, 0x6B, 0xC1, 0xF0, 0x0F } }

/*
 *   X(pid, name, guid, ep_in, ep_in_peer, ep_out, ep_out_peer,
 *     unused_in_ep, drain_on_opcode, settle_ms, flags)
 */
/* Order matters: within a PID the daemon picks the first row whose required
 * endpoints are all present. The II+ (6 endpoints) must come before the T48
 * (4) and T56 (2) because they share PID 0x0A53; the 0x83 peer is what tells
 * the II+ apart. */
#define XGPRO_MODEL_TABLE(X)                                            \
    X(0x0A53, "TL866II Plus", XGPRO_GUID_T48,                           \
      0x82, 0x83, 0x02, 0x03, 0x00, 0x00, 1000,                         \
      XGPRO_F_DUAL_PAYLOAD)                                             \
    X(0x0A53, "T48", XGPRO_GUID_T48,                                    \
      0x82, 0x00, 0x02, 0x00, 0x00, 0x00, 1000, 0)                      \
    X(0x0A53, "T56", XGPRO_GUID_T48,                                    \
      0x81, 0x00, 0x01, 0x00, 0x00, 0x00, 1000, 0)                      \
    X(0x1A86, "T76", XGPRO_GUID_T76,                                    \
      0x82, 0x00, 0x05, 0x00, 0x83, 0x0D, 1000,                         \
      XGPRO_F_DRAIN_BEFORE_READ)

#endif /* XGPRO_MODELS_H */
