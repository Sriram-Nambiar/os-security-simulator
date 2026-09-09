/* ====================================================================
   WINDOWS PROCESS SCHEDULER SIMULATION
   ====================================================================
   This program simulates the core CONCEPT behind how Microsoft Windows
   schedules processes/threads on the CPU. It is NOT a real operating
   system and does NOT use the actual Win32 scheduler code - it is a
   simplified software MODEL built to demonstrate the underlying ideas:

     1. PRIORITY-BASED PREEMPTIVE SCHEDULING
        Windows assigns every thread a priority (0-31 in real Windows).
        The CPU always runs the READY thread with the HIGHEST priority.
        A running thread can be PREEMPTED (interrupted) if a higher
        priority thread becomes ready.

     2. TIME QUANTUM
        Each thread only gets to run for a limited "slice" of CPU time
        (a quantum) before the scheduler re-evaluates who should run.

     3. DYNAMIC PRIORITY BOOSTING
        Real Windows temporarily RAISES a thread's priority after it
        finishes waiting on I/O (disk, keyboard, network, etc.), so
        interactive/IO-bound processes feel more responsive. The
        priority then DECAYS back down to its base level over time.

   SIMPLIFICATIONS (explained further in the written report):
     - Real Windows has 32 priority levels split into priority CLASSES;
       here we use a simplified range of 1 (lowest) to 15 (highest).
     - Real Windows quantums vary by edition/foreground status; here we
       use one fixed quantum for clarity.
     - Threads are modeled as simple "processes" for simplicity.
   ==================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PROCESSES   20
#define MAX_PRIORITY    15   /* highest priority value  */
#define MIN_PRIORITY    1    /* lowest priority value   */
#define QUANTUM         4    /* fixed time slice (ms)   */
#define BOOST_AMOUNT    3    /* how much priority jumps after I/O wait */

typedef enum { NEW, READY, RUNNING, WAITING, TERMINATED } State;

/* A process here can have UP TO TWO CPU bursts with one I/O wait in
   between them (phase 0 = first CPU burst, phase 1 = I/O wait,
   phase 2 = second CPU burst, phase 3 = done). This is enough to
   clearly demonstrate the block-on-I/O -> boost-on-return behaviour
   without over-complicating the model. If io_burst is 0, the process
   is purely CPU-bound and never blocks. */
typedef struct {
    int  pid;
    int  base_priority;      /* priority the process starts/returns to  */
    int  current_priority;   /* priority actually used by the scheduler */
    int  arrival_time;
    int  cpu_burst1;         /* first CPU burst length                   */
    int  io_burst;           /* how long it waits on I/O (0 = no I/O)    */
    int  cpu_burst2;         /* second CPU burst length (0 if none)      */
    int  remaining_cpu;      /* CPU time left in the CURRENT phase       */
    int  remaining_io;       /* time left waiting on I/O                 */
    int  phase;              /* 0=CPU1, 1=I/O, 2=CPU2, 3=done            */
    int  waiting_time;
    int  turnaround_time;
    int  start_time;
    int  finished;
    State state;
} Process;

Process proc[MAX_PROCESSES];
int proc_count = 0;

/* ---- simple ready queue implemented as one array per priority level ---- */
int ready_queue[MAX_PRIORITY + 1][MAX_PROCESSES];
int ready_count[MAX_PRIORITY + 1];

void enqueue(int priority, int pid) {
    ready_queue[priority][ready_count[priority]++] = pid;
}

/* remove and return the pid at the front of a given priority's queue */
int dequeue(int priority) {
    int pid = ready_queue[priority][0];
    for (int i = 1; i < ready_count[priority]; i++)
        ready_queue[priority][i - 1] = ready_queue[priority][i];
    ready_count[priority]--;
    return pid;
}

/* find the highest priority level that currently has a ready process */
int highest_ready_priority() {
    for (int p = MAX_PRIORITY; p >= MIN_PRIORITY; p--)
        if (ready_count[p] > 0) return p;
    return -1; /* nothing ready */
}

void print_state(Process *pr) {
    const char *names[] = {"NEW", "READY", "RUNNING", "WAITING", "TERMINATED"};
    printf("%-10s", names[pr->state]);
}

/* ---------------------------------------------------------------------
   Load a preset demo set of processes that clearly shows preemption
   and priority boosting in action.
   --------------------------------------------------------------------- */
void load_demo_processes() {
    /* prio, arrival, cpu_burst1, io_burst, cpu_burst2 */
    struct { int prio, arrival, cpu1, io, cpu2; } demo[] = {
        {4,  0, 4, 3, 4},   /* P1: low priority, blocks for I/O mid-way  */
        {6,  1, 6, 0, 0},   /* P2: medium priority, pure CPU work        */
        {10, 3, 2, 2, 2},   /* P3: high priority, interactive, does I/O  */
        {4,  4, 5, 0, 0},   /* P4: low priority, background CPU work     */
    };
    int n = sizeof(demo) / sizeof(demo[0]);
    for (int i = 0; i < n; i++) {
        Process *pr = &proc[proc_count];
        pr->pid = proc_count + 1;
        pr->base_priority = demo[i].prio;
        pr->current_priority = demo[i].prio;
        pr->arrival_time = demo[i].arrival;
        pr->cpu_burst1 = demo[i].cpu1;
        pr->io_burst = demo[i].io;
        pr->cpu_burst2 = demo[i].cpu2;
        pr->remaining_cpu = demo[i].cpu1;
        pr->remaining_io = 0;
        pr->phase = 0;
        pr->waiting_time = 0;
        pr->turnaround_time = 0;
        pr->start_time = -1;
        pr->finished = 0;
        pr->state = NEW;
        proc_count++;
    }
}

void add_custom_process() {
    if (proc_count >= MAX_PROCESSES) {
        printf("Process list full.\n");
        return;
    }
    Process *pr = &proc[proc_count];
    pr->pid = proc_count + 1;

    printf("Enter base priority (%d-%d): ", MIN_PRIORITY, MAX_PRIORITY);
    scanf("%d", &pr->base_priority);
    if (pr->base_priority < MIN_PRIORITY) pr->base_priority = MIN_PRIORITY;
    if (pr->base_priority > MAX_PRIORITY) pr->base_priority = MAX_PRIORITY;
    pr->current_priority = pr->base_priority;

    printf("Enter arrival time: ");
    scanf("%d", &pr->arrival_time);

    printf("Enter first CPU burst time: ");
    scanf("%d", &pr->cpu_burst1);
    pr->remaining_cpu = pr->cpu_burst1;

    printf("Enter I/O burst time (0 for none): ");
    scanf("%d", &pr->io_burst);
    pr->remaining_io = 0;

    if (pr->io_burst > 0) {
        printf("Enter second CPU burst time (after I/O): ");
        scanf("%d", &pr->cpu_burst2);
    } else {
        pr->cpu_burst2 = 0;
    }

    pr->phase = 0;
    pr->waiting_time = 0;
    pr->turnaround_time = 0;
    pr->start_time = -1;
    pr->finished = 0;
    pr->state = NEW;

    proc_count++;
    printf("Process P%d added.\n", pr->pid);
}

/* ---------------------------------------------------------------------
   The core scheduling loop. Runs tick-by-tick (1 unit of simulated time
   per iteration) so we can clearly print what happens at every step -
   this is what makes a good report screenshot / explanation.
   --------------------------------------------------------------------- */
void run_scheduler() {
    memset(ready_count, 0, sizeof(ready_count));

    int finished_count = 0;
    int time = 0;
    int running_pid = -1;      /* pid currently on the CPU, -1 = idle */
    int quantum_used = 0;

    printf("\n===================== SIMULATION START =====================\n");

    while (finished_count < proc_count && time < 200) {

        /* 1. Move any newly-arrived processes into the ready queue */
        for (int i = 0; i < proc_count; i++) {
            if (proc[i].state == NEW && proc[i].arrival_time == time) {
                proc[i].state = READY;
                enqueue(proc[i].current_priority, proc[i].pid);
                printf("[t=%3d] P%d ARRIVES  (priority %d)\n",
                       time, proc[i].pid, proc[i].current_priority);
            }
        }

        /* 2. Move any processes finishing I/O wait back to ready,
              applying the Windows-style PRIORITY BOOST                */
        for (int i = 0; i < proc_count; i++) {
            if (proc[i].state == WAITING) {
                proc[i].remaining_io--;
                if (proc[i].remaining_io <= 0) {
                    proc[i].state = READY;
                    proc[i].phase = 2;
                    proc[i].remaining_cpu = proc[i].cpu_burst2;
                    int boosted = proc[i].base_priority + BOOST_AMOUNT;
                    if (boosted > MAX_PRIORITY) boosted = MAX_PRIORITY;
                    proc[i].current_priority = boosted;
                    enqueue(proc[i].current_priority, proc[i].pid);
                    printf("[t=%3d] P%d finishes I/O -> BOOSTED to priority %d\n",
                           time, proc[i].pid, boosted);
                }
            }
        }

        /* 3. Decide who should run this tick (preemption check) */
        int best_priority = highest_ready_priority();
        Process *running = (running_pid != -1) ? &proc[running_pid - 1] : NULL;

        if (running == NULL) {
            /* CPU idle - pick the highest priority ready process */
            if (best_priority != -1) {
                running_pid = dequeue(best_priority);
                running = &proc[running_pid - 1];
                running->state = RUNNING;
                if (running->start_time == -1) running->start_time = time;
                quantum_used = 0;
                printf("[t=%3d] P%d STARTS running (priority %d)\n",
                       time, running->pid, running->current_priority);
            }
        } else if (best_priority > running->current_priority) {
            /* A higher-priority process just became ready -> PREEMPT */
            running->state = READY;
            enqueue(running->current_priority, running->pid);
            printf("[t=%3d] P%d PREEMPTED by higher priority process\n",
                   time, running->pid);

            running_pid = dequeue(best_priority);
            running = &proc[running_pid - 1];
            running->state = RUNNING;
            if (running->start_time == -1) running->start_time = time;
            quantum_used = 0;
            printf("[t=%3d] P%d STARTS running (priority %d)\n",
                   time, running->pid, running->current_priority);
        }

        /* 4. Execute one tick of the running process, if any */
        for (int i = 0; i < proc_count; i++) {
            if (proc[i].state == READY) proc[i].waiting_time++;
        }

        if (running != NULL) {
            running->remaining_cpu--;
            quantum_used++;

            int done_burst = (running->remaining_cpu <= 0);
            int quantum_expired = (quantum_used >= QUANTUM);

            if (done_burst && running->phase == 0 && running->io_burst > 0) {
                /* First CPU burst finished and this process needs I/O */
                running->state = WAITING;
                running->phase = 1;
                running->remaining_io = running->io_burst;
                printf("[t=%3d] P%d BLOCKS for I/O (%d ticks)\n",
                       time + 1, running->pid, running->io_burst);
                running_pid = -1;

            } else if (done_burst && (running->phase == 2 || running->io_burst == 0)) {
                /* Process fully finished all its work */
                running->phase = 3;
                running->state = TERMINATED;
                running->finished = 1;
                running->turnaround_time = time + 1 - running->arrival_time;
                finished_count++;
                printf("[t=%3d] P%d TERMINATED (turnaround=%d)\n",
                       time + 1, running->pid, running->turnaround_time);
                running_pid = -1;

            } else if (quantum_expired) {
                /* Quantum expired: Windows would DECAY priority slightly
                   for CPU-bound processes that never block on I/O       */
                running->state = READY;
                if (running->current_priority > running->base_priority)
                    running->current_priority--;  /* decay boosted priority */
                enqueue(running->current_priority, running->pid);
                printf("[t=%3d] P%d QUANTUM EXPIRED -> back to ready (priority %d)\n",
                       time + 1, running->pid, running->current_priority);
                running_pid = -1;
            }
        }

        time++;
    }

    printf("===================== SIMULATION END =======================\n\n");
}

void print_summary() {
    printf("%-6s%-10s%-10s%-10s%-14s%-14s\n",
           "PID", "Priority", "Arrival", "CPUBurst", "Waiting", "Turnaround");
    for (int i = 0; i < proc_count; i++) {
        printf("P%-5d%-10d%-10d%-10d%-14d%-14d\n",
               proc[i].pid, proc[i].base_priority, proc[i].arrival_time,
               proc[i].cpu_burst1 + proc[i].cpu_burst2, proc[i].waiting_time, proc[i].turnaround_time);
    }

    double avg_wait = 0, avg_turn = 0;
    for (int i = 0; i < proc_count; i++) {
        avg_wait += proc[i].waiting_time;
        avg_turn += proc[i].turnaround_time;
    }
    avg_wait /= proc_count;
    avg_turn /= proc_count;
    printf("\nAverage Waiting Time:    %.2f ticks\n", avg_wait);
    printf("Average Turnaround Time: %.2f ticks\n", avg_turn);
}

int main() {
    int choice;

    printf("======================================================\n");
    printf(" WINDOWS PRIORITY-BASED PREEMPTIVE SCHEDULER - SIMULATOR\n");
    printf("======================================================\n");
    printf("1. Run PRESET demo (recommended - shows preemption + boosting)\n");
    printf("2. Enter CUSTOM processes\n");
    printf("Choice: ");
    scanf("%d", &choice);

    if (choice == 2) {
        int n;
        printf("How many processes? ");
        scanf("%d", &n);
        for (int i = 0; i < n; i++) {
            printf("\n--- Process %d ---\n", i + 1);
            add_custom_process();
        }
    } else {
        load_demo_processes();
        printf("\nLoaded %d preset processes:\n", proc_count);
        printf("%-6s%-10s%-10s%-10s%-10s\n", "PID", "Priority", "Arrival", "CPU", "IO");
        for (int i = 0; i < proc_count; i++)
            printf("P%-5d%-10d%-10d%-10d%-10d\n", proc[i].pid, proc[i].base_priority,
                   proc[i].arrival_time, proc[i].cpu_burst1 + proc[i].cpu_burst2, proc[i].io_burst);
    }

    run_scheduler();
    print_summary();

    return 0;
}