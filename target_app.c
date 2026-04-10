/*
 * QNX Deterministic Security Monitor - Target Application Currently running as a normal workload
 * Priority Level: 10 (Normal - SCHEDULED_RoundRobin)
 * Use 'A' to toggle attack simulation that spikes CPU usage
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <termios.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/dispatch.h>
#include "security_ipc.h"

#ifndef EOK
#define EOK 0
#endif

static volatile int attack_mode = 0;
static volatile int halted = 0;

/*
 * Keyboard listener thread. That can be triggered ro replicate an attack
 */
static void* keyboard_thread(void *arg) {
    struct termios oldt, newt;

    (void)arg;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (!halted) {
        char ch = getchar();
        if (ch == 'a' || ch == 'A') {
            attack_mode = !attack_mode;
            if (attack_mode) {
                printf("\n");
                printf("  ***********************************************\n");
                printf("  *   >>> ATTACK SIMULATION ACTIVATED <<<       *\n");
                printf("  *   Spiking CPU to simulate Flush+Reload      *\n");
                printf("  *   Press 'A' again to deactivate             *\n");
                printf("  ***********************************************\n\n");
            } else {
                printf("\n  [ATTACK OFF] Returning to normal operation\n\n");
            }
        } else if (ch == 'q' || ch == 'Q') {
            halted = 1;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return NULL;
}

int main(int argc, char *argv[]) {
    int fd, coid;
    procfs_info info;
    uint64_t last_cputime = 0;
    int anomaly_score = 0;
    struct timespec ts;
    struct sched_param param;
    pthread_t kbd_tid;

    (void)argc;
    (void)argv;

    /* Set process priority to 10 (Normal) with round-robin scheduling */
    param.sched_priority = 10;
    if (sched_setscheduler(0, SCHED_RR, &param) == -1) {
        perror("[TARGET_APP] Cannot set priority");
    }

    printf("=========================================================\n");
    printf("  QNX DETERMINISTIC SECURITY MONITOR - Target Application\n");
    printf("  PID: %d | Priority: 10 | Scheduler: SCHED_RR\n", getpid());
    printf("=========================================================\n\n");

    /* Open our own /proc entry for real telemetry */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/as", getpid());
    fd = open(proc_path, O_RDONLY);
    if (fd == -1) {
        perror("[TARGET_APP] Failed to open /proc");
        return 1;
    }

    /* Connect to Security Monitor via QNX named IPC */
    coid = name_open(SEC_MONITOR_NAME, 0);
    if (coid == -1) {
        perror("[TARGET_APP] Cannot connect to Security Monitor");
        printf("[TARGET_APP] Make sure security_monitor is running first!\n");
        close(fd);
        return 1;
    }

    printf("[TARGET_APP] Connected to Security Monitor (coid=%d)\n", coid);
    printf("[TARGET_APP] Reading REAL /proc telemetry for PID %d\n", getpid());
    printf("[TARGET_APP] Press 'A' to simulate attack, 'Q' to quit\n\n");

    /* Start keyboard listener in a separate thread */
    if (pthread_create(&kbd_tid, NULL, keyboard_thread, NULL) != 0) {
        perror("[TARGET_APP] Failed to create keyboard thread");
    }

    while (!halted) {
        /* ===== ATTACK SIMULATION ===== */
        /* When active, burn CPU to naturally spike /proc metrics */
        if (attack_mode) {
            volatile unsigned long sum = 0;
            int i;
            for (i = 0; i < 5000000; i++) {
                sum += (unsigned long)i * (unsigned long)i;
            }
        }

        /* ===== READ REAL TELEMETRY FROM /proc ===== */
        if (devctl(fd, DCMD_PROC_INFO, &info, sizeof(info), NULL) == EOK) {
            /* CPU time = user time + system time (nanoseconds from kernel) */
            uint64_t cputime = info.utime + info.stime;
            uint64_t cpu_delta = cputime - last_cputime;
            last_cputime = cputime;

            /* Convert to microseconds */
            unsigned long delta_us = (unsigned long)(cpu_delta / 1000);

            /* Anomaly scoring: high CPU delta = suspicious activity */
            if (attack_mode && delta_us > 5000) {
                anomaly_score = (int)((delta_us - 5000) / 500) * 3;
                if (anomaly_score > 100) anomaly_score = 100;
            } else {
                anomaly_score = delta_us > 12000 ? (int)((delta_us - 12000) / 1000) * 3 : 0;
                if (anomaly_score > 100) anomaly_score = 100;
            }

            /* Display telemetry */
            printf("  [%s] CPU: %8lu us | Delta: %6lu us | Score: %3d",
                   attack_mode ? "ATTACK" : "NORMAL",
                   (unsigned long)(cputime / 1000), delta_us, anomaly_score);

            /* ===== SYNCHRONOUS IPC via MsgSend ===== */
            /* This is the key QNX feature: the target blocks until the
               Security Monitor processes and replies to this message. */
            security_msg_t msg;
            security_reply_t reply;

            memset(&msg, 0, sizeof(msg));
            msg.type         = SECURITY_MSG_TYPE;
            msg.subtype      = 0;
            msg.sender_pid   = getpid();
            msg.cpu_time_us  = cputime / 1000;
            msg.cpu_delta_us = delta_us;
            msg.anomaly_score = anomaly_score;
            msg.attack_active = attack_mode;

            memset(&reply, 0, sizeof(reply));

            if (MsgSend(coid, &msg, sizeof(msg), &reply, sizeof(reply)) == -1) {
                printf(" | IPC: FAILED (%s)\n", strerror(errno));
            } else {
                if (reply.status == 1) {
                    /* Security Monitor has ordered us to halt */
                    printf(" | >>> HALTED <<<\n");
                    printf("\n  *****************************************************\n");
                    printf("  *  PROCESS HALTED BY MITIGATION ENGINE              *\n");
                    printf("  *  Threat Level: %-3d                                *\n", reply.threat_level);
                    printf("  *  This process is being shut down for security.    *\n");
                    printf("  *****************************************************\n\n");
                    halted = 1;
                } else {
                    printf(" | OK\n");
                }
            }
        }

        /* 500ms deterministic tick */
        ts.tv_sec = 0;
        ts.tv_nsec = 500000000;
        nanosleep(&ts, NULL);
    }

    printf("[TARGET_APP] Shutting down (PID: %d)\n", getpid());
    close(fd);
    name_close(coid);
    return 0;
}
