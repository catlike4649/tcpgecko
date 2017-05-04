#ifndef _MAIN_H_
#define _MAIN_H_

#include "common/types.h"
#include "dynamic_libs/os_functions.h"

/* Main */
#ifdef __cplusplus
extern "C" {
#endif

#define COMPUTER_IP_ADDRESS "192.168.2.103"

//! C wrapper for our C++ functions
int Menu_Main(void);

extern bool isCodeHandlerInstalled;

#ifdef __cplusplus
}
#endif

#endif
