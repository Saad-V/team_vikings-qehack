/*
 * QNX Deterministic Security Monitor - Shared IPC Header
 * Defines message structures and constants for inter-process communication
 * between Target App, Security Monitor, and Mitigation Engine.
 */

#ifndef SECURITY_IPC_H
#define SECURITY_IPC_H

#include <stdint.h>
#include <sys/types.h>

/* ===== Channel Names (used with name_attach / name_open) ===== */
#define SEC_MONITOR_NAME    "security_monitor"
#define MITIGATION_NAME     "mitigation_engine"

/* ===== Custom Message Type (must not conflict with QNX system types) ===== */
#define SECURITY_MSG_TYPE   0x1000

/* ===== Pulse Codes (user-defined, must be >= 0; system codes are negative) ===== */
#define PULSE_CODE_ALERT    1   /* Emergency alert: monitor -> mitigation */

/* ===== Defaults ===== */
#define DEFAULT_THRESHOLD   25

/* ===== Telemetry Message: target_app -> security_monitor (via MsgSend) ===== */
typedef struct {
    uint16_t    type;           /* Must be SECURITY_MSG_TYPE */
    uint16_t    subtype;        /* Reserved, set to 0 */
    pid_t       sender_pid;     /* PID of the sending process */
    uint64_t    cpu_time_us;    /* Total CPU time in microseconds */
    uint64_t    cpu_delta_us;   /* CPU time delta since last sample */
    int         anomaly_score;  /* Calculated anomaly score (0-100) */
    int         attack_active;  /* 1 if attack simulation is active */
} security_msg_t;

/* ===== Reply: security_monitor -> target_app (via MsgReply) ===== */
typedef struct {
    int         status;         /* 0 = OK (continue), 1 = HALT (threat detected) */
    int         threat_level;   /* Severity level of detected threat */
} security_reply_t;

#endif /* SECURITY_IPC_H */
