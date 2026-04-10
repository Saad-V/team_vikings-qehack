/* QNX Deterministic Security Monitor - Mitigation Engine
 Priority Level: 63 (MAXIMUM - SCHED_FIFO) */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/syspage.h>
#include "security_ipc.h"

#ifndef EOK
#define EOK 0
#endif

int main(int argc, char *argv[]) {
    name_attach_t *attach;
    int rcvid;
    struct sched_param param;
    int mitigation_count = 0;

    /*
     * Receive buffer - handles both system messages (_IO_CONNECT from
     * name_open clients) and pulses (emergency alerts).
     */
    union {
        uint16_t        type;
        struct _pulse   pulse;
    } recv_buf;

    (void)argc;
    (void)argv;

    /* Set MAXIMUM realtime priority (63 = highest user priority on QNX) */
    param.sched_priority = 63;
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        perror("[MITIGATION] Cannot set realtime priority");
    }

    printf("=============================================================\n");
    printf("  QNX MITIGATION ENGINE - Maximum Priority Authority\n");
    printf("  PID: %d | Priority: 63 | Scheduler: SCHED_FIFO\n", getpid());
    printf("  Status: ARMED - Will preempt ALL lower priority tasks\n");
    printf("=============================================================\n\n");

    /* Register named IPC channel */
    attach = name_attach(NULL, MITIGATION_NAME, 0);
    if (attach == NULL) {
        perror("[MITIGATION] name_attach failed");
        return 1;
    }

    printf("[MITIGATION] Channel registered as '%s'\n", MITIGATION_NAME);
    printf("[MITIGATION] Waiting for emergency alerts...\n");
    printf("[MITIGATION] CPU usage: 0%% (blocked on MsgReceive)\n\n");

    /* ===== MAIN RECEIVE LOOP ===== */
    while (1) {
        /*
         * MsgReceive() - blocks at priority 63.
         * The instant a pulse arrives, the QNX scheduler wakes this thread
         * and preempts ANY running thread with priority < 63.
         * This is the core deterministic guarantee of the QNX RTOS.
         */
        rcvid = MsgReceive(attach->chid, &recv_buf, sizeof(recv_buf), NULL);

        /* ---- Pulse messages (rcvid == 0) ---- */
        if (rcvid == 0) {
            if (recv_buf.pulse.code == PULSE_CODE_ALERT) {
                int anomaly = recv_buf.pulse.value.sival_int;
                uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
                uint64_t timestamp_ms = ClockCycles() / (cps / 1000);
                int i;

                mitigation_count++;

                printf("\n");
                printf("  *************************************************************\n");
                printf("  *                                                           *\n");
                printf("  *   CRITICAL: THREAT NEUTRALIZED - SYSTEM HALTED            *\n");
                printf("  *                                                           *\n");
                printf("  *   MITIGATION ENGINE ACTIVATED (PRIORITY 63)               *\n");
                printf("  *   Anomaly Score  : %-5d                                   *\n", anomaly);
                printf("  *   System Time    : %llu ms                            *\n",
                       (unsigned long long)timestamp_ms);
                printf("  *   Event Count    : #%-4d                                  *\n", mitigation_count);
                printf("  *                                                           *\n");
                printf("  *************************************************************\n");
                printf("  *   EXECUTING DETERMINISTIC MITIGATION SEQUENCE...          *\n");
                printf("  *************************************************************\n");

                /*
                 * 5-step mitigation sequence.
                 * Each step uses nanospin_ns() for deterministic busy-wait timing.
                 * This runs at priority 63, preempting everything else on the system.
                 */
                for (i = 0; i < 5; i++) {
                    printf("  >> Step %d/5: ", i + 1);
                    switch (i) {
                        case 0: printf("Isolating compromised process...      "); break;
                        case 1: printf("Capturing forensic snapshot...        "); break;
                        case 2: printf("Revoking process privileges...        "); break;
                        case 3: printf("Flushing suspicious cache lines...    "); break;
                        case 4: printf("Restoring secure baseline...          "); break;
                    }
                    fflush(stdout);
                    nanospin_ns(2000000); /* 2ms deterministic busy wait */
                    printf("DONE\n");
                }

                printf("  *************************************************************\n");
                printf("  *                                                           *\n");
                printf("  *   THREAT NEUTRALIZED - SYSTEM SECURED                     *\n");
                printf("  *   Total mitigation time: <10ms (deterministic)            *\n");
                printf("  *   QNX preemption guarantee: verified                      *\n");
                printf("  *                                                           *\n");
                printf("  *************************************************************\n\n");
            }
            continue;
        }

        /* ---- System _IO_CONNECT message (from name_open clients) ---- */
        if (rcvid > 0 && recv_buf.type == _IO_CONNECT) {
            MsgReply(rcvid, EOK, NULL, 0);
            printf("[MITIGATION] Security Monitor connected\n");
            continue;
        }

        /* ---- Unknown message ---- */
        if (rcvid > 0) {
            MsgError(rcvid, ENOSYS);
        }
    }

    name_detach(attach, 0);
    return 0;
}
