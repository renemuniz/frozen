#ifndef ECS_H_
#define ECS_H_

#include <stdint.h>
#include <stdarg.h>

#define PROGNAME "ecs"
#define UNUSED(x) (void)x;

/* undef here for release build */
#define DEBUG

#define IPC_BY_MQUEUE
#define HTTP_BY_WGET
#define MUTEX_LOCK_BY_SEMAPHORE

#if defined(IPC_BY_MQUEUE)
#define MAX_QUEUE_SIZE 4096
#define QUEUE_NAME  "/ecs_queue"
#endif

#ifdef DEBUG
#define DBG_PRT(fmt, ...) fprintf(stderr, PROGNAME": [%-15.15s] %-10.10s:%d - "fmt"\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DBG_PRT_ARR( a, sz )  do { DBG_PRT(""); \
                                    fprintf(stderr, #a"[%d]: (hex) ", (sz)); \
                                    int my_dbg_index = 0; \
                                    for( ; my_dbg_index < (sz); my_dbg_index++ ) \
                                    {\
                                       if( 0 == my_dbg_index % 16 )\
                                       {\
                                          fprintf(stderr, "0x%02X: ", my_dbg_index);\
                                       }\
                                       fprintf(stderr, "%02hhX ", ((char*)a)[my_dbg_index]); \
                                       if( 15 == my_dbg_index % 16 )\
                                       {\
                                          fprintf(stderr, "\n");\
                                       }\
                                    }\
                                    fprintf(stderr, "%s", ( 15 != my_dbg_index % 16 ) ? "\n": ""); \
                               } while(0);
#else
#define DBG_PRT(...)
 #define DBG_PRT_ARR(...)
#endif

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

typedef void *(* callback)(void *parameter, ...);

/*
 * timed callback
 */

typedef struct _pocTimedCallback {
    callback doPOCTimedCallback;
    int remainingTime; // in seconds
    uint8_t timer;
    char description[12];
} pocTimedCallback;

#define PING_BASE_URL "http://127.0.0.1/poc/generic/api/ping/v1_0/serial/"
#define STATUS_BASE_URL "http://127.0.0.1/poc/generic/api/status/v1_0/serial/"
// for debug mode
#define PING_BODY_URL "/poc/generic/api/ping/v1_0/serial/"
#define STATUS_BODY_URL "/poc/generic/api/status/v1_0/serial/"

#define PING_TIMER 30
#define STATUS_TIMER 120

#endif /* #ifndef ECS_H_ */