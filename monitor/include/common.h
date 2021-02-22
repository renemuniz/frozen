#ifndef COMMON_H_
#define COMMON_H_

#define PROGNAME "launcher"
#define ECS_PATH "./ecs &"
#define DCA_PATH "./dca &"
#define RELAUNCH_DELAY 30
#define SHORT_DELAY 2 // wait time to launch ECS after DCA

/* undef here for release build */
#define DEBUG

#ifdef DEBUG
#define DBG_PRT(fmt, ...) fprintf(stderr, PROGNAME": [%-15.15s] %-10.10s:%d - "fmt"\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DBG_PRT(...)
#endif

#endif /* #ifndef COMMON_H_ */