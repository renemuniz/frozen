#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <mqueue.h>
#include <unistd.h>
#include <signal.h>

/* Define mutex strategy here */
#define MUTEX_LOCK_BY_SEMAPHORE // reported to work on kernel >= 2.6

/* Define app execution strategy here */
#define LAUNCH_BY_SYSTEM_LIBC // uses system() stdlib call, very portable, blocking call

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#include <semaphore.h>
#endif

#if defined(MUTEX_LOCK_BY_FLOCK)
#include <sys/file.h>
#endif

#include "common.h"

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#define SEM_NAME "/monitor_001"

int getMutexLock() {
    sem_t *sem;
    int rc;

    sem = sem_open(SEM_NAME, O_CREAT, S_IRWXU, 1);

    if (sem == SEM_FAILED) {
        DBG_PRT("sem_open: failed errno:%d", errno);
        return 1;
    }

    rc = sem_trywait(sem);

    if (rc) {
        DBG_PRT("Lock not obtained, another instance is running");
        return 2;
    }

    return 0;
}

void releaseMutexResources() {
    sem_unlink(SEM_NAME);
}
#elif defined(MUTEX_LOCK_BY_DOMAIN_UNIX_SOCKET)
int getMutexLock() {
    // implements mutex mechanism by creating exclusive unix domain socket
}

void releaseMutexResources() {}
#elif defined(MUTEX_LOCK_BY_FLOCK)
#define PID_FILE "/tmp/monitor.pid"

int getMutexLock() {
    // implements mutex mechanism by creating temporary file with exclusive access flag
    int pid_file = open(PID_FILE, O_CREAT | O_RDWR, 0666);
    int rc = flock(pid_file, LOCK_EX | LOCK_NB);

    if (rc) {
        if (EWOULDBLOCK == errno) {
            DBG_PRT("Lock not obtained, another instance is running");
            return 1;
        } else {
            DBG_PRT("Error while getting mutex: %d", errno);
            return 2;
        }
    }
    else {
        return 0;
    }
}

void releaseMutexResources() {
    remove(PID_FILE);
}
#endif

#if defined(LAUNCH_BY_SYSTEM_LIBC)
int launchClient() {
    return system(ECS_PATH);
}

int launchDCA() {
    return system(DCA_PATH);
}
#endif

void sigHandler(int signal) {
    DBG_PRT("[LAUNCHER] Caught signal %d", signal);
    releaseMutexResources();
    exit(1);
}

/*
 * ---------------------------
 * MONITOR / LAUNCHER
 * ---------------------------
 *
 * This application is responsible for launching client and monitoring its execution.
 * In case of failure, client must be restarted.
 * Only one instance is globally allowed.
 *
 * Monitor will start, acquire a global mutex and then run an infinite loop launching client every
 * X seconds. Client will also have a mutex allowing just one global instance. All logic beyond this is omitted.
 *
 */

int main(int argc, char **argv) {
    int rc;
    static char firstRun = 0;

    DBG_PRT("MONITOR START");

    if (getMutexLock()) {
        return 0;
    }

    signal(SIGINT, sigHandler);
    signal(SIGABRT, sigHandler);
    signal(SIGKILL, sigHandler);
    signal(SIGSEGV, sigHandler);
    signal(SIGTERM, sigHandler);

    DBG_PRT("MONITOR START");

    while (1) {
        // launch processes in background
        rc = launchDCA();

        // give some room to DCA start and create mqueue
        sleep(SHORT_DELAY);

        rc = launchClient();

        if (!firstRun) {
            firstRun = 1;
            DBG_PRT("[LAUNCHER] Client is now operational");
        }

        // TODO: fail detection mechanism
        sleep(RELAUNCH_DELAY);
    }

    releaseMutexResources();
    DBG_PRT("MONITOR END");
}
