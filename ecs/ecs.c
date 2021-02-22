#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "ecs.h"

#if defined(IPC_BY_MQUEUE)
#include <mqueue.h>
#endif

#if defined(HTTP_BY_WGET)
#include <wget.h>
#endif

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#include <semaphore.h>
#endif

#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include <aes.h>

deviceInformation deviceInfo;
networkInformation networkInfo;

// for DEBUG mode
char g_debug_mode = 0; // defaults to cloud
uint16_t g_debug_port = 5000;
char g_debug_ip[16]; // includes EOS

/*
 *
 * ---------
 * ECS - POC
 * ---------
 *
 * Client POC: Only two functions are implemented
 *
 * - PING: Every 30 seconds
 * - ping responses:
 *   - systemReboot();
 *   - getSystemInformation();
 *   - getNetworkInformation();
 *   - wifiReset();
 *   - writeToLocalStorage();
 *   - readFromLocalStorage();
 *
 */

#if defined(IPC_BY_MQUEUE)
mqd_t mq;
struct mq_attr attr;
// command + 4Kb + EOS + spare
char buffer[MAX_QUEUE_SIZE + 3];

int initIPC() {
    mq = mq_open(QUEUE_NAME, O_RDWR);

    if (mq == -1) {
        DBG_PRT("Error creating message queue");

        return -1;
    }

    return 0;
}

// blocking call
int ipcRead() {
    int bytes_read = mq_receive(mq, buffer, MAX_QUEUE_SIZE + 3, NULL);

    if (bytes_read < 0) {
        DBG_PRT("IPC Error: %s", strerror(errno));
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
        DBG_PRT("[ECS] IPC write OK");
    }

    return 0;
}

int sendIPCCommand(uint8_t command, char withFeedback) {
    int res;

    res = ipcWrite(&command, sizeof(command));

    if (res) {
        DBG_PRT("[ECS] Error while writing to IPC queue. Error code: %d", res);
        return -1;
    }

    if (withFeedback) {
        if (ipcRead()) {
            DBG_PRT("[ECS] Error while reading from IPC queue");
            return -1;
        }
    }

    return 0;
}

int sendIPCBuffer(char* ipcBuffer, size_t size, char withFeedback) {
    int res;

    res = ipcWrite(ipcBuffer, size);

    if (res) {
        DBG_PRT("[ECS] Error while writing to IPC queue. Error code: %d", res);
        return -1;
    }

    if (withFeedback) {
        if (ipcRead()) {
            DBG_PRT("[ECS] Error while reading from IPC queue");
            return -1;
        }
    }

    return 0;
}
#endif

#if defined(HTTP_BY_WGET)
void globalInitHTTP() {
    wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
    wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);
    wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

    wget_global_init(0);
}

void globalDeInitHTTP() {
    wget_net_deinit();
}
#endif

#if defined(MUTEX_LOCK_BY_SEMAPHORE)
#define SEM_NAME "/ecs_001"

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

#define MAX_HANDLERS 10
pocTimedCallback g_timedCallbacks[MAX_HANDLERS];

void initTimedCallbacks() {
    for (uint8_t i = 0; i < MAX_HANDLERS; ++i) {
        g_timedCallbacks[i].doPOCTimedCallback = NULL;
        g_timedCallbacks[i].remainingTime = -1; // -1 == disabled
        g_timedCallbacks[i].timer = 0;
        memset(g_timedCallbacks[i].description, 0, sizeof(g_timedCallbacks[i].description));
    }
}

void installTimedCallback(callback timedCallback, int timerInSeconds, uint8_t timer, uint8_t index, char * description) {
    if (index > MAX_HANDLERS - 1) {
        DBG_PRT("[ECS] Invalid callback %d", index);

        return;
    }

    // uninstall callback
    if (timerInSeconds == -1) {
        DBG_PRT("[ECS] Uninstalling callback %d", index);
        g_timedCallbacks[index].doPOCTimedCallback = NULL;
        g_timedCallbacks[index].remainingTime = -1;
        g_timedCallbacks[index].description[0] = 0;

        return;
    }

    if (!timedCallback) {
        DBG_PRT("[ECS] Invalid callback pointer");

        return;
    }

    if (!timer) {
        DBG_PRT("[ECS] Invalid timer, must be a positive number");

        return;
    }

    g_timedCallbacks[index].doPOCTimedCallback = timedCallback;
    g_timedCallbacks[index].remainingTime = timerInSeconds;
    g_timedCallbacks[index].timer = timer;

    if (description && strlen(description)) {
        strncpy(g_timedCallbacks[index].description, description, sizeof(g_timedCallbacks[index].description));
    }

    DBG_PRT("[ECS] Callback installed %d", index);
}

// each time called, decrement in 1 second
void updateTimers() {
    for (uint8_t i = 0; i < MAX_HANDLERS; ++i) {
        if (g_timedCallbacks[i].remainingTime > 0)
            g_timedCallbacks[i].remainingTime -= 1;
    }
}

void executeCallbacks() {
    for (uint8_t i = 0; i < MAX_HANDLERS; ++i) {
        if (g_timedCallbacks[i].remainingTime == 0 && g_timedCallbacks[i].doPOCTimedCallback) {

            // custom action handling
            if (!strcmp(g_timedCallbacks[i].description, "ping")) {
                g_timedCallbacks[i].doPOCTimedCallback(deviceInfo.serialNumber);
            } else if (!strcmp(g_timedCallbacks[i].description, "status")) {
                char macAddress[13] = {0};

                for (char i = 0; i < 6; ++i) {
                    sprintf(&macAddress[i * 2], "%02hhX", networkInfo.macAddress[i]);
                }

                g_timedCallbacks[i].doPOCTimedCallback(deviceInfo.serialNumber, macAddress, networkInfo.connectedDevices, networkInfo.ssid_24, networkInfo.ssid_5);
            } else {
                g_timedCallbacks[i].doPOCTimedCallback(NULL);
            }

            // after callback execution, reset its timer
            g_timedCallbacks[i].remainingTime = g_timedCallbacks[i].timer;
        }
    }
}

/*
 * Perform Ping command
 *
 * Receive serial number as parameter
 *
 */
void *doPing(void *parameter, ...) {
    if (!parameter || !strlen((char *) parameter)) {
        DBG_PRT("[ECS] PING callback: invalid serial number");
        return NULL;
    }

    char url[100] = {0};
    uint8_t command;
    int res;
    char port[7] = {0};

    wget_iri *uri;
    wget_http_connection *conn = NULL;
    wget_http_request *req;

    if (!g_debug_mode) {
        strcpy(url, PING_BASE_URL);
        strcat(url, (char *) parameter);
    } else {
        strcpy(url, "http://");
        strcat(url, g_debug_ip);
        strcat(url, ":");

        sprintf(port, "%d", g_debug_port);

        strcat(url, port);
        strcat(url, PING_BODY_URL);
        strcat(url, (char *) parameter);
    }

    uri = wget_iri_parse(url, NULL);
    req = wget_http_create_request(uri, "GET");

    if (!req) {
        DBG_PRT("[ECS-PING] Error creating request");
        goto out_1;
    }

    wget_http_add_header(req, "User-Agent", "POCClient/1.0");
    wget_http_add_header(req, "Accept", "*/*");
    wget_http_add_header(req, "Cache-Control", "no-cache");
    wget_http_add_header(req, "Accept-Encoding", "gzip, deflate");

    res = wget_http_open(&conn, uri);

    if (res != WGET_E_SUCCESS) {
        DBG_PRT("[ECS-PING] HTTP open error");
        goto out_1;
    }

    if (conn) {
        wget_http_response *resp;

        if (wget_http_send_request(conn, req) == 0) {
            resp = wget_http_get_response(conn);

            if (!resp)
                goto out;

            if (!resp->keep_alive)
                wget_http_close(&conn);

            DBG_PRT("HTTP Code: %d", resp->code);

            if (resp->code == 200) {
                uint16_t operation = (((uint16_t) resp->body->data[0]) << 8) | (uint16_t) resp->body->data[1];

                switch (operation) {
                    case 0:
                        // reboot device
                        DBG_PRT("[ECS] Reboot device command received");
                        command = 0; // system reboot
                        res = sendIPCCommand(command, 0);

                        if (res) {
                            DBG_PRT("[ECS-SysReboot] IPC Error.");
                        }

                        break;

                    case 1:
                        // reset wifi settings
                        DBG_PRT("[ECS] Wifi reset command received");
                        command = 3; // reset wifi
                        res = sendIPCCommand(command, 1);

                        if (res) {
                            DBG_PRT("[ECS-WifiReset] IPC Error.");
                            break;
                        }

                        if (!strcmp(buffer, "OK")) {
                            DBG_PRT("[ECS-WifiReset] Operation performed normally");
                        } else {
                            DBG_PRT("[ECS-WifiReset] Operation error");
                        }

                        break;

                    default:
                        DBG_PRT("[ECS] Warning: unknown command received: %d", operation);
                }
            }

            wget_http_free_response(&resp);
        }
    }

out:
    wget_http_close(&conn);
    wget_http_free_request(&req);
out_1:
    wget_iri_free(&uri);

    return NULL;
}

// will encrypt data, apply 16 rounding and return a newly allocated heap buffer
int encryptPacket(const unsigned char *input, size_t size, unsigned char **output) {
    if (!input || !size) {
        DBG_PRT("[ECS] Encryption error: null packet passed in");
        return -1;
    }

    unsigned char key[32] = "\x5A\x14\x41\x79\x4F\x47\x56\xAD\x5A\x44\x5A\x68\x5A\x47\x55\x79\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    unsigned char iv[16] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    mbedtls_aes_context aes;

    // apply padding
    size_t paddingCounter = 16 - (size % 16);
    *output = (unsigned char *) malloc(size + paddingCounter);

    if (!(*output)) {
        DBG_PRT("[ECS] Encryption error: memory allocation error");
        return -1;
    }

    memset(*output, 0, size + paddingCounter);
    memcpy(*output, input, size + paddingCounter);

    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, size + paddingCounter, iv, *output, *output);

    return size + paddingCounter;
}

// add header to encrypted packet
int addHeader(unsigned char **packet, size_t size) {
    if (!size || !(*packet)) {
        DBG_PRT("[ECS] Append header error: null packet passed in");
        return -1;
    }

    *packet = realloc(*packet, size + 3);

    if (!(*packet)) {
        DBG_PRT("[ECS] Append header error: memory allocation error");
        return -1;
    }

    memcpy(*packet + 3, *packet, size);

    *((*packet) + 0)= 'v';
    *((*packet) + 1) = 1;
    *((*packet) + 2) = 0;

    return size + 3;
}

/*
 * Perform Status
 *
 * - Serial number is passed in parameter;
 * - Varargs are, in order: MAC, number of devices, ssid24, ssid50
 */

void *doStatus(void *parameter, ...) {
    unsigned char packet[160] = {0};
    unsigned char *packet_enc = NULL;

    if (!parameter || !strlen((char *) parameter)) {
        DBG_PRT("[ECS-Status] Status callback: invalid serial number");
        return NULL;
    }

    char *serialNumber = parameter;

    va_list args;
    va_start(args, parameter);

    char *macAddress = va_arg(args, char *);

    if (!macAddress || !strlen(macAddress)) {
        DBG_PRT("[ECS-Status] Status callback: invalid MAC address");
        return NULL;
    }

    uint8_t numberOfDevices = (uint8_t) va_arg(args, int);

    char *ssid24 = va_arg(args, char *);

    if (!ssid24 || !strlen(ssid24)) {
        DBG_PRT("[ECS-Status] Status callback: invalid ssid24");
        return NULL;
    }

    char *ssid50 = va_arg(args, char *);

    if (!ssid50 || !strlen(ssid50)) {
        DBG_PRT("[ECS-Status] Status callback: invalid ssid50");
        return NULL;
    }

    va_end(args);

    strcat(packet, serialNumber);
    strcat(packet, macAddress);

    packet[strlen(packet)] = numberOfDevices;

    packet[strlen(packet)] = strlen(ssid24);
    strcat(packet, ssid24);

    packet[strlen(packet)] = strlen(ssid50);
    strcat(packet, ssid50);

    int totalSize = encryptPacket(packet, strlen(packet), &packet_enc);
    totalSize = addHeader(&packet_enc, totalSize);

    DBG_PRT_ARR(packet_enc, totalSize)

    char url[100] = {0};
    char port[7] = {0};

    wget_iri *uri;
    wget_http_connection *conn = NULL;
    wget_http_request *req;

    if (!g_debug_mode) {
        strcpy(url, STATUS_BASE_URL);
        strcat(url, (char *) parameter);
    } else {
        strcpy(url, "http://");
        strcat(url, g_debug_ip);
        strcat(url, ":");

        sprintf(port, "%d", g_debug_port);

        strcat(url, port);
        strcat(url, STATUS_BODY_URL);
        strcat(url, (char *) parameter);
    }

    uri = wget_iri_parse(url, NULL);
    req = wget_http_create_request(uri, "POST");

    if (!req) {
        DBG_PRT("[ECS-STATUS] Error creating request");
        goto out_1;
    }

    wget_http_add_header(req, "User-Agent", "POCClient/1.0");
    wget_http_add_header(req, "Content-Type", "application/octet-stream");
    wget_http_request_set_body(req, "application/octet-stream", packet_enc, totalSize);

    int res = wget_http_open(&conn, uri);

    if (res != WGET_E_SUCCESS) {
        DBG_PRT("[ECS-PING] HTTP open error");
        goto out_1;
    }

    if (conn) {
        wget_http_response *resp;

        if (wget_http_send_request(conn, req) == 0) {
            resp = wget_http_get_response(conn);

            if (!resp)
                goto out;

            if (!resp->keep_alive)
                wget_http_close(&conn);

            DBG_PRT("HTTP Code: %d", resp->code);

            wget_http_free_response(&resp);
        }
    }

    out:
    wget_http_close(&conn);
    wget_http_free_request(&req);
    out_1:
    wget_iri_free(&uri);

    return NULL;
}

void printUsage() {
    printf("----------\n");
    printf("ECS Usage:\n");
    printf("----------\n\n");

    printf("If you use ecs without arguments, it will automatically use our cloud servers\n");
    printf("If you want to test with our test server (does not require internet access) please do:\n\n");
    printf("ecs -d -i <local ip address where test server is running at> -p <port: defaults to 5000>\n\n");
    printf("example: ecs -d -i 192.168.0.20 -p 5000\n");
}

void sigHandler(int signal) {
    DBG_PRT("[ECS] Caught signal %d", signal);
    releaseMutexResources();
    exit(1);
}

int main(int argc, char **argv) {
    int res;
    uint8_t command;

    if (getMutexLock()) {
        return 0;
    }

    signal(SIGINT, sigHandler);
    signal(SIGABRT, sigHandler);
    signal(SIGKILL, sigHandler);
    signal(SIGSEGV, sigHandler);
    signal(SIGTERM, sigHandler);

    DBG_PRT("[ECS] ECS START");

    // parse command line to check for debug mode
    opterr = 0;

    while ((res = getopt(argc, argv, "di:p:")) != -1) {
        switch (res) {
            case 'd':
                g_debug_mode = 1;
                break;

            case 'i':
                if (!strlen(optarg) || strlen(optarg) > 15) {
                    printUsage();
                    return -1;
                }

                strcpy(g_debug_ip, optarg);
                break;

            case 'p':
                g_debug_port = atoi(optarg);

                if (!g_debug_port) {
                    printf("Error: port must be a numeric value\n");
                    printUsage();
                    return -1;
                }
                break;

            case '?':
                if (optopt == 'i') {
                    printf("Error: option i requires a parameter\n");
                    printUsage();
                    return -1;
                } else if (optopt == 'p') {
                    printf("Error: option i requires a parameter\n");
                    printUsage();
                    return -1;
                } else {
                    printf("Error: Unknown option %c\n", optopt);
                    printUsage();
                    return -1;
                }

                break;

            default:
                printf("Error: Unknown option\n");
                printUsage();
                return -1;

                break;
        }
    }

    if (g_debug_mode) {
        DBG_PRT("[ECS] ECS STARTED IN DEBUG MODE");
        DBG_PRT("** TEST IP: %s", g_debug_ip);
        DBG_PRT("** TEST PORT: %d", g_debug_port);
    } else {
        DBG_PRT("[ECS] ECS STARTED IN PRODUCTION MODE");
    }

    globalInitHTTP();
    res = initIPC();

    if (res) {
        DBG_PRT("[ECS] Error while initializing IPC. Error code: %d", res);
        return -1;
    }

    // get platform serial number needed for APIs
    command = 1; // get device information
    res = sendIPCCommand(command, 1);

    if (res) {
        DBG_PRT("[ECS] IPC Error. Aborting.");
        return -1;
    }

    memcpy(&deviceInfo, buffer, sizeof(deviceInformation));

    DBG_PRT("[ECS] Device Information - serial number: %s", deviceInfo.serialNumber);
    DBG_PRT("[ECS] Device Information - software version: %s", deviceInfo.softwareVersion);
    DBG_PRT("[ECS] Device Information - hardware version: %s", deviceInfo.hardwareVersion);

    // now get network parameters, needed as well
    command = 2; // get device information
    res = sendIPCCommand(command, 1);

    if (res) {
        DBG_PRT("[ECS] IPC Error. Aborting.");
        return -1;
    }

    memcpy(&networkInfo, buffer, sizeof(networkInformation));

    DBG_PRT_ARR(networkInfo.macAddress, 6);
    DBG_PRT("[ECS] Network Information - SSID 2.4: %s", networkInfo.ssid_24);
    DBG_PRT("[ECS] Network Information - SSID 5: %s", networkInfo.ssid_5);
    DBG_PRT("[ECS] Network Information - Connected devices: %d", networkInfo.connectedDevices);

    // setup callbacks
    initTimedCallbacks();
    installTimedCallback(doPing, PING_TIMER, PING_TIMER, 0, "ping");
    installTimedCallback(doStatus, STATUS_TIMER, STATUS_TIMER, 1, "status");

    // just for testing purposes, read from local storage
    command = 5; // read from LocalStorage
    res = sendIPCCommand(command, 1);

    if (res) {
        DBG_PRT("[ECS] IPC Error. Aborting.");
        return -1;
    }

    DBG_PRT("[ECS] ReadFromLocalStorage performed normally");
    DBG_PRT_ARR(buffer, (int) strlen(buffer));

    // now write something to LocalStorage
    char *lsBuffer = malloc(MAX_QUEUE_SIZE + 1);

    if (!lsBuffer) {
        DBG_PRT("[ECS] Memory allocation error. Aborting.");
        return -1;
    }

    // just dummy data
    memset(lsBuffer, '2', MAX_QUEUE_SIZE + 1);
    lsBuffer[0] = 4; // write to local storage

    // TODO: Research why posix API fails to transfer more than 4Kb data
    res = sendIPCBuffer(lsBuffer, MAX_QUEUE_SIZE, 1);

    if (res) {
        DBG_PRT("[ECS] IPC Error. Aborting.");
        return -1;
    }

    if (!strcmp(buffer, "OK")) {
        DBG_PRT("[ECS] WriteToLocalStorege performed normally");
    } else {
        DBG_PRT("[ECS] WriteToLocalStorege error");
    }

    free(lsBuffer);

    DBG_PRT("[ECS] ECS MAIN LOOP START");

    do {
        executeCallbacks();
        sleep(1);
        updateTimers();
        DBG_PRT("[ECS] ECS MAIN LOOP SLEEP...");
    } while (1);

    globalDeInitHTTP();
    releaseMutexResources();

    return 0;
}