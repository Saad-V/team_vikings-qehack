# Real-Time Threat Detection & Mitigation System
A split-architecture, real-time threat detection system engineered strictly for the **QNX Neutrino RTOS**. 

This project uses microkernel isolation and priority-based preemptive scheduling to deterministically identify and mitigate microarchitectural attacks in embedded environments. By replacing non-deterministic high computational overhead with a high-speed C-native engine, this system guarantees microsecond response times without compromising system stability.

##  Core Features of The Project

* **Microkernel Fault Isolation:** The security layer operates in a completely separate memory space from standard applications. Even if the target application is fully compromised, it cannot crash or tamper with the defense mechanism.
* **Native Deterministic IPC:** Eliminates insecure shared memory by routing all telemetry and threat alerts through synchronous QNX Message Passing techniques like `MsgSend()`, `MsgReceive()`, `MsgReply()`.
* **Priority-Based Preemption:** Utilizes strict RTOS thread management. The mitigation engine runs at critical priority (63), allowing the QNX scheduler to instantly halt compromised processes the exact microsecond an anomaly is detected.
* **Real `/proc` Telemetry:** Uses hardware abstractions of VMWare by parsing live OS-level metrics (CPU cycles, context switches) directly from the QNX filesystem.

---

##  System Architecture

The system consists of three isolated C programs communicating exclusively via the QNX microkernel.

### 1. Target Application (`target_app.c`)
* **Priority Level:** 10 (Normal - `SCHED_RR`)
* **Role:** Simulates a mission-critical enterprise application. It continuously reads its own live OS-level metrics from the QNX `/proc/<pid>/as` filesystem and streams them via IPC to the Monitor. 
* **Attack Vector:** Includes a raw terminal keyboard listener. Pressing `A` simulates a side-channel attack by rapidly burning CPU cycles by running an infinite loop to mimic an active exploit footprint.

### 2. Security Monitor (`security_monitor.c`)
* **Priority Level:** 21 (High - `SCHED_FIFO`)
* **Role:** The heuristic algorithmic brain. It sits blocked at 0% CPU overhead waiting for `MsgReceive()`. Once telemetry arrives, it parses the data. If the anomaly score breaches the hardcoded threshold, it fires an asynchronous, non-blocking **Pulse** to the Mitigation Engine.

### 3. Mitigation Engine (`mitigation_engine.c`)
* **Priority Level:** 63 (Critical Maximum - `SCHED_FIFO`)
* **Role:** The ultimate system authority. It sleeps entirely dormant until triggered by the Monitor's pulse. Upon receiving the alert, the QNX scheduler guarantees this thread **instantly preempts all lower-priority tasks**, taking 100% control of the CPU to deterministically halt the attack and lock down the system.

---

## 📂 Repository Structure

```text
├── target_app.c          # Telemetry generator and simulated vulnerable application
├── security_monitor.c    # Heuristic threat detection engine
├── mitigation_engine.c   # Priority 63 preemption and system lock-down
├── security_ipc.h        # Shared definitions, structs, and IPC channel names
|-- Demo_video.mp4
└── README.md             # Project documentation

