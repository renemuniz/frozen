#ifndef DCA_H_
#define DCA_H_

#include <stdint.h>
#include <stdarg.h>

#define PROGNAME "DCA"
#define UNUSED(x) (void)x;

/* undef here for release build */
#define DEBUG

#define MUTEX_LOCK_BY_SEMAPHORE
#define IPC_BY_MQUEUE

#if defined(IPC_BY_MQUEUE)
#define MAX_QUEUE_SIZE 4096
#define QUEUE_NAME  "/dca_queue"
#endif

#ifdef DEBUG
#define DBG_PRT(fmt, ...) fprintf(stderr, PROGNAME": [%-15.15s] %-10.10s:%d - "fmt"\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DBG_PRT(...)
#endif

/*
 * Callbacks definition
 */

typedef void *(* callback)(void *parameter, ...);

typedef struct _supportedOperations {
    callback reboot; // system reboot
    callback getDeviceInformation;
    callback getNetworkInformation;
    callback wifiReset;
    callback writeToLocalStorage;
    callback readFromLocalStorage;
} supportedOperations;

/*
 * For getDeviceInformation API
 */
#define SERIAL_NUMBER_SIZE 20
#define FW_VERSION_SIZE 4
#define HW_VERSION_SIZE 2

typedef struct _deviceInformation {
    char serialNumber[SERIAL_NUMBER_SIZE]; // zero terminated string
    char softwareVersion[FW_VERSION_SIZE]; // always 4 bytes long
    char hardwareVersion[HW_VERSION_SIZE]; // always 2 bytes long
} deviceInformation;

/*
 * for getNetworkInformation API
 */
#define MAC_SIZE 6
#define SSID_SIZE 33 // including null termination
typedef struct _networkInformation {
    char macAddress[MAC_SIZE];
    char ssid_24[SSID_SIZE]; // for 2.4 GHz network
    char ssid_5[SSID_SIZE]; // for 5 GHz network
    uint16_t connectedDevices;
} networkInformation;

#endif /* #ifndef DCA_H_ */