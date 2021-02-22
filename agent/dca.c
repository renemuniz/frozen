#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "dca.h"

#if defined(IPC_BY_MQUEUE)
#include <mqueue.h>
#endif

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#include <semaphore.h>
#endif

#include <unistd.h>
#include <signal.h>

/*
 * --------------
 *      DCA
 * --------------
 *
 * The DCA (device client application) is responsible for performing the actions fired by client application.
 * Actions are received by listening to a posix message queue. As the actions are platform dependent, this is only
 * a skeleton to serve as an implementation example.
 *
 */

supportedOperations g_operations;

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#define SEM_NAME "/dca_001"

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
#endif

/*
 * Perform system reboot
 *
 * parameter: pass NULL to this struct as is not needed
 *
 */
void *systemReboot(void *parameter, ...) {
    UNUSED(parameter)

    DBG_PRT("[DCA] ** System Reboot called **");

    return NULL;
}

/*
 * Get relevant system information parameters
 *
 * parameter: pass NULL to this struct as is not needed
 * returns heap allocated struct in memory or NULL in case of failure
 * caller is in charge of memory dealloc
 *
 */
void *getSystemInformation(void *parameter, ...) {
    UNUSED(parameter)

    // dummy data
    deviceInformation *dc = (deviceInformation *) malloc(sizeof(deviceInformation));

    if (!dc) {
        DBG_PRT("memory allocation error");
        return NULL;
    }

    dc->hardwareVersion[0] = 1;
    dc->hardwareVersion[1] = 0;

    dc->softwareVersion[0] = 1;
    dc->softwareVersion[1] = 2;
    dc->softwareVersion[2] = 3;
    dc->softwareVersion[3] = 4;

    strcpy(dc->serialNumber, "90LHI010950001037");

    return dc;
}

/*
 * Get relevant system network parameters
 *
 * parameter: pass NULL to this struct as is not needed
 * returns heap allocated struct in memory or NULL in case of failure
 * caller is in charge of memory dealloc
 *
 */
void *getNetworkInformation(void *parameter, ...) {
    UNUSED(parameter)

    // dummy data
    networkInformation *nc = (networkInformation *) malloc(sizeof(networkInformation));

    if (!nc) {
        DBG_PRT("memory allocation error");
        return NULL;
    }

    nc->macAddress[0] = 1;
    nc->macAddress[1] = 2;
    nc->macAddress[2] = 3;
    nc->macAddress[3] = 4;
    nc->macAddress[4] = 5;
    nc->macAddress[5] = 6;

    nc->connectedDevices = 10;

    strcpy(nc->ssid_24, "2.4Ghz_network");
    strcpy(nc->ssid_5, "5Ghz_network");

    return nc;
}

/*
 * Wifi reset function
 *
 * parameter: pass NULL to this struct as is not needed
 * returns NULL on success or a int * with error code on failure
 * caller is in charge of memory dealloc if required
 *
 */
void *wifiReset(void *parameter, ...) {
    UNUSED(parameter)

    DBG_PRT("[DCA] ** WIFI Reset called **");

    return NULL;
}

/*
 * Write to local storage
 *
 * Persist relevant data to a non-volatile memory area
 * returns NULL on success or a int * with error code on failure
 *
 * parameter: buffer to be written to NVM
 * size: the first integer parameter passed in va_arg (maximum is 4Kb)
 *
 */
void *writeToLocalStorage(void *parameter, ...) {
    if (!parameter) {
        int *result = (int *) malloc(sizeof(int));

        if (result) {
            DBG_PRT("Error: null pointer passed in");
            *result = 1;

            return result;
        } else {
            DBG_PRT("Error: memory allocation error");

            return NULL;
        }
    }

    va_list args;
    va_start(args, parameter);

    int size = va_arg(args, int);

    if (!size || size > MAX_QUEUE_SIZE) {
        int *result = (int *) malloc(sizeof(int));

        if (result) {
            DBG_PRT("Error: invalid size");
            *result = 2;
            va_end(args);

            return result;
        } else {
            DBG_PRT("Error: memory allocation error");
            va_end(args);

            return NULL;
        }
    }

    // now we have size, write buffer data to non-volatile memory and return
    // as an example, write data to tmpfs
    FILE *outFile = NULL;

    outFile = fopen("/tmp/localstorage.bin", "wb");

    if (!outFile) {
        int *result = (int *) malloc(sizeof(int));

        if (result) {
            DBG_PRT("Error: can't write to LocalStorage");
            *result = 3;
            va_end(args);

            return result;
        } else {
            DBG_PRT("Error: memory allocation error");
            va_end(args);

            return NULL;
        }
    }

    fwrite(parameter, size, 1, outFile);
    fclose(outFile);

    va_end(args);
    return NULL;
}

/*
 * Read from local storage
 *
 * Read relevant data from non-volatile memory area
 * returns NULL on failure or a heap allocated area containing data read
 * caller is in charge of memory dealloc
 *
 */
void *readFromLocalStorage(void *parameter, ...) {
    if (!parameter) {
        DBG_PRT("[readFromLocalStorage] Error: null pointer passed in.");

        return NULL;
    }

    // as an example, read from tmpfs
    if (access("/tmp/localstorage.bin", F_OK) != -1) {
        // file exists
        FILE *inputFile = fopen("/tmp/localstorage.bin", "rb");

        if (!inputFile) {
            DBG_PRT("[readFromLocalStorage] Error: can't read from LocalStorage");

            return NULL;
        }

        fseek(inputFile, 0, SEEK_END);
        long fSize = ftell(inputFile);

        if (fSize > MAX_QUEUE_SIZE) {
            // this should never happen
            DBG_PRT("[readFromLocalStorage] Error: LocalStorage limits exceeded.");
            fclose(inputFile);

            return NULL;
        }

        fseek(inputFile, 0, SEEK_SET);
        char *lsBuffer = (char *) malloc(fSize);

        if (!lsBuffer) {
            DBG_PRT("[readFromLocalStorage] Error: Memory allocation error.");
            fclose(inputFile);

            return NULL;
        }

        fread(lsBuffer, 1, fSize, inputFile);
        fclose(inputFile);

        // assume parameter as pointer to int already allocated in heap
        int *outSize = (int *) parameter;
        *outSize = (int) fSize;

        return (void *) lsBuffer;
    } else {
        // file doesn't exist, return just dummy data
        int total_read = 100; // 100 bytes read, dummy value
        char *lsBuffer = (char *) malloc(total_read); // dummy buffer

        if (!lsBuffer) {
            DBG_PRT("[readFromLocalStorage] Error: Memory allocation error.");

            return NULL;
        }

        // fill with random data
        memset(lsBuffer, '1', total_read);

        // assume parameter as pointer to int already allocated in heap
        int *outSize = (int *) parameter;
        *outSize = 100;

        return (void *) lsBuffer;
    }
}

/*
 * Init all supported operations on a given device
 */
void initOperations() {
    g_operations.reboot = systemReboot;
    g_operations.getDeviceInformation = getSystemInformation;
    g_operations.getNetworkInformation = getNetworkInformation;
    g_operations.wifiReset = wifiReset;
    g_operations.writeToLocalStorage = writeToLocalStorage;
    g_operations.readFromLocalStorage = readFromLocalStorage;
}

#if defined(IPC_BY_MQUEUE)
mqd_t mq;
struct mq_attr attr;
// command + 4Kb + EOS + spare
char buffer[MAX_QUEUE_SIZE + 3];

int initIPC() {
    /* initialize queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = MAX_QUEUE_SIZE + 2; // 4Kb + command + EOS
    attr.mq_curmsgs = 0;

    mq = mq_open(QUEUE_NAME, O_CREAT | O_RDWR, 0666, &attr);

    if (mq == -1) {
        DBG_PRT("Error creating message queue");

        return -1;
    }

    return 0;
}

// configured as blocking call
int ipcRead() {
    int bytes_read = mq_receive(mq, buffer, MAX_QUEUE_SIZE + 3, NULL);

    if (bytes_read < 0) {
        DBG_PRT("IPC Error: %d", bytes_read);
        return -1;
    }

    buffer[bytes_read] = '\0';

    return 0;
}

int ipcWrite(void *data, int size) {
    if (!data || !size) {
        DBG_PRT("IPC Error: null pointer passed in to write function");
        return -1;
    }

    int res =  mq_send(mq, (char *) data, size, 0);

    if (res) {
        DBG_PRT("IPC Error: Error writing to queue: %s", strerror(errno));
        return res;
    } else {
        DBG_PRT("[DCA] IPC write OK");
    }

    return 0;
}

void deInitIPC(mqd_t mq) {
    mq_close(mq);
}
#endif

void sigHandler(int signal) {
    DBG_PRT("[DCA] Caught signal %d", signal);
    releaseMutexResources();
    deInitIPC(mq);
    exit(1);
}

int main(int argc, char **argv) {
    int res;

    if (getMutexLock()) {
        return 0;
    }

    signal(SIGINT, sigHandler);
    signal(SIGABRT, sigHandler);
    signal(SIGKILL, sigHandler);
    signal(SIGSEGV, sigHandler);
    signal(SIGTERM, sigHandler);

    DBG_PRT("DCA START");
    initOperations();

    res = initIPC();

    if (res) {
        DBG_PRT("Error while initializing IPC. Error code: %d", res);
        return -1;
    }

    DBG_PRT("DCA MAIN LOOP START");

    do {
        // read command from mqueue and take action accordingly
        if (!ipcRead()) {
            switch (buffer[0]) {
                // system reboot
                case 0:
                    DBG_PRT("[DCA] System reboot called");
                    g_operations.reboot(NULL);
                    break;

                // get device information
                case 1:
                    DBG_PRT("[DCA] getDeviceInformation() called");

                    deviceInformation *deviceData = (deviceInformation *) g_operations.getDeviceInformation(NULL);

                    if (!deviceData) {
                        DBG_PRT("[DCA] getDeviceInformation() returned NULL data!");
                        break;
                    }

                    DBG_PRT("[DCA] getDeviceInformation(): sending data to client...");
                    ipcWrite(deviceData, sizeof(deviceInformation));
                    DBG_PRT("[DCA] getDeviceInformation(): data sent!");
                    free(deviceData);

                    break;

                // get network information
                case 2:
                    DBG_PRT("[DCA] getNetworkInformation() called");
                    networkInformation *networkData = (networkInformation *) g_operations.getNetworkInformation(NULL);

                    if (!networkData) {
                        DBG_PRT("[DCA] getNetworkInformation() returned NULL data!");
                        break;
                    }

                    DBG_PRT("[DCA] getNetworkInformation(): sending data to client...");
                    ipcWrite(networkData, sizeof(networkInformation));
                    DBG_PRT("[DCA] getNetworkInformation(): data sent!");
                    free(networkData);

                    break;

                // wifi reset
                case 3:
                    DBG_PRT("[DCA] wifiReset() called");
                    int *resetResult = g_operations.wifiReset(NULL);

                    if (!resetResult) {
                        DBG_PRT("[DCA] wifiReset() success!");
                        ipcWrite("OK", 2);
                    } else {
                        DBG_PRT("[DCA] wifiReset() error: %d", *resetResult);
                        ipcWrite("NOK", 2);
                        free(resetResult);
                    }

                    break;

                // write to local storage
                case 4:
                    DBG_PRT("[DCA] writeToLocalStorage() called");

                    // skip first byte (command)
                    int *writeToLocalStorageResult =  g_operations.writeToLocalStorage(&buffer[1], strlen(&buffer[1]));

                    if (!writeToLocalStorageResult) {
                        DBG_PRT("[DCA] writeToLocalStorage() success!");
                        ipcWrite("OK", 2);
                    } else {
                        DBG_PRT("[DCA] writeToLocalStorage() error: %d", *writeToLocalStorageResult);
                        ipcWrite("NOK", 2);
                        free(writeToLocalStorageResult);
                    }

                    break;

                // read from local storage
                case 5:
                    DBG_PRT("[DCA] readFromLocalStorage() called");
                    int readSize = 0;
                    char *readData = (char *) g_operations.readFromLocalStorage(&readSize);

                    if (!readData || !readSize) {
                        DBG_PRT("[DCA] readFromLocalStorage(): error reading from NVM");
                        break;
                    }

                    ipcWrite((void *) readData, readSize);
                    DBG_PRT("[DCA] readFromLocalStorage(): data sent!");
                    free(readData);

                    break;
            } // switch
        }
    } while (1);

    releaseMutexResources();

    return 0;
}