/*
 * QNX Deterministic Security Monitor - Heuristic Engine
 * Priority Level: 21 (Realtime - SCHED_FIFO)
 * The algorithmic brain of the system. Sits blocked on MsgReceive()
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include "security_ipc.h"

#ifndef EOK
#define EOK 0
#endif

int main(int argc, char *argv[]) {
    name_attach_t *attach;
    int coid_mitigation;
    int threshold = DEFAULT_THRESHOLD;
    int rcvid;
    struct sched_param param;
    int alert_count = 0;
    int total_msgs = 0;

    /*
     * Receive buffer - must be large enough for any incoming message type.
     * Using a union so we can inspect the type field first, then cast.
     */
    union {
        uint16_t        type;
        struct _pulse   pulse;
        security_msg_t  sec_msg;
    } recv_buf;

    /* Set priority to 21 (Realtime) with FIFO scheduling */
    param.sched_priority = 21;
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        perror("[SEC_MONITOR] Cannot set realtime priority");
    }

    /* Accept dynamic threshold from command line */
    if (argc > 1) {
        threshold = atoi(argv[1]);
        if (threshold < 5 || threshold > 100) threshold = DEFAULT_THRESHOLD;
    }

    printf("=========================================================\n");
    printf("  QNX SECURITY MONITOR - Heuristic Detection Engine\n");
    printf("  PID: %d | Priority: 21 | Scheduler: SCHED_FIFO\n", getpid());
    printf("  Anomaly Threshold: %d\n", threshold);
    printf("=========================================================\n\n");

    /* Register named IPC channel */
    attach = name_attach(NULL, SEC_MONITOR_NAME, 0);
    if (attach == NULL) {
        perror("[SEC_MONITOR] name_attach failed");
        return 1;
    }

    /* Connect to Mitigation Engine (may not be running yet) */
    coid_mitigation = name_open(MITIGATION_NAME, 0);
    if (coid_mitigation == -1) {
        printf("[SEC_MONITOR] WARNING: Mitigation Engine not connected\n");
        printf("[SEC_MONITOR] Will retry on first alert\n");
    } else {
        printf("[SEC_MONITOR] Connected to Mitigation Engine\n");
    }

    printf("[SEC_MONITOR] IPC Channel ready (chid=%d)\n", attach->chid);
    printf("[SEC_MONITOR] Listening for telemetry from Target App...\n\n");

    /* ===== MAIN RECEIVE LOOP ===== */
    while (1) {
        /*
         * MsgReceive() blocks until a message or pulse arrives.
         * This is deterministic QNX IPC - zero polling, zero CPU waste.
         */
        rcvid = MsgReceive(attach->chid, &recv_buf, sizeof(recv_buf), NULL);

        /* ---- Pulse messages (rcvid == 0) ---- */
        if (rcvid == 0) {
            switch (recv_buf.pulse.code) {
                case _PULSE_CODE_DISCONNECT:
                    printf("[SEC_MONITOR] Client disconnected\n");
                    break;
                default:
                    break;
            }
            continue;
        }

        /* ---- Error ---- */
        if (rcvid == -1) {
            perror("[SEC_MONITOR] MsgReceive error");
            continue;
        }

        /* ---- System _IO_CONNECT message (from name_open clients) ---- */
        if (recv_buf.type == _IO_CONNECT) {
            MsgReply(rcvid, EOK, NULL, 0);
            printf("[SEC_MONITOR] Client connected via name_open()\n");
            continue;
        }

        /* ---- Our custom security telemetry message ---- */
        if (recv_buf.type == SECURITY_MSG_TYPE) {
            security_msg_t *msg = &recv_buf.sec_msg;
            security_reply_t reply;

            memset(&reply, 0, sizeof(reply));
            total_msgs++;

            /* Display received telemetry */
            printf("  [MSG #%04d] PID:%-6d | CPU Delta: %6lu us | Score: %3d | %s",
                   total_msgs,
                   msg->sender_pid,
                   (unsigned long)msg->cpu_delta_us,
                   msg->anomaly_score,
                   msg->attack_active ? "ATTACK" : "NORMAL");

            /* ===== THRESHOLD CHECK ===== */
            if (msg->anomaly_score >= threshold) {
                alert_count++;
                printf(" --> !!! ALERT #%d !!!\n", alert_count);

                /* Retry connection to Mitigation Engine if needed */
                if (coid_mitigation == -1) {
                    coid_mitigation = name_open(MITIGATION_NAME, 0);
                    if (coid_mitigation != -1) {
                        printf("[SEC_MONITOR] Reconnected to Mitigation Engine\n");
                    }
                }

                /* Forward emergency pulse to Mitigation Engine */
                if (coid_mitigation != -1) {
                    if (MsgSendPulse(coid_mitigation, 21, PULSE_CODE_ALERT,
                                     msg->anomaly_score) == -1) {
                        printf("[SEC_MONITOR] Mitigation IPC failed: %s\n",
                               strerror(errno));
                    } else {
                        printf("[SEC_MONITOR] Emergency alert forwarded to Mitigation Engine\n");
                    }
                } else {
                    printf("[SEC_MONITOR] WARNING: Cannot reach Mitigation Engine!\n");
                }

                /* Reply to Target App with HALT command */
                reply.status = 1;
                reply.threat_level = msg->anomaly_score;
                MsgReply(rcvid, EOK, &reply, sizeof(reply));
            } else {
                /* Normal - tell target to continue */
                printf(" --> OK\n");
                reply.status = 0;
                reply.threat_level = 0;
                MsgReply(rcvid, EOK, &reply, sizeof(reply));
            }
            continue;
        }

        /* ---- Unknown message type ---- */
        if (rcvid > 0) {
            MsgError(rcvid, ENOSYS);
        }
    }

    name_detach(attach, 0);
    return 0;
}
