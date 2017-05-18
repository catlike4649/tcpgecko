#include "bit.h"
#include "stringify.h"
#include "../dynamic_libs/os_functions.h"
#include "threads.h"
#include "../system/exception_handler.h"
#include "../utils/logger.h"
#include "../main.h"

#ifndef TCPGECKO_BREAKPOINTS_H
#define TCPGECKO_BREAKPOINTS_H

static inline int getBreakpointAddress(void *interruptedContext, int threadOffset) {
	return *((int *) interruptedContext + threadOffset);
}

#define DATA_ADDRESS_BREAKPOINT_OFFSET 0xA4

static inline int getDataAddressBreakpointAddressMatch(void *interruptedContext) {
	return getBreakpointAddress(interruptedContext, DATA_ADDRESS_BREAKPOINT_OFFSET);
}

#define INSTRUCTION_ADDRESS_BREAKPOINT_OFFSET 0x98

static inline int getInstructionBreakpointAddressMatch(void *interruptedContext) {
	return getBreakpointAddress(interruptedContext, INSTRUCTION_ADDRESS_BREAKPOINT_OFFSET);
}

unsigned char breakPointHandler(void *interruptedContext) {
	log_init(COMPUTER_IP_ADDRESS);

	// Check for data breakpoints
	int dataAddress = getDataAddressBreakpointAddressMatch(interruptedContext);
	if (OSIsAddressValid((const void *) dataAddress)) {
		log_printf("Data breakpoint address: %x08", dataAddress);
	} else {
		log_print("Data breakpoint failed!");

		// Check for instruction breakpoints
		int instructionAddress = getInstructionBreakpointAddressMatch(interruptedContext);
		if (OSIsAddressValid((const void *) instructionAddress)) {
			log_printf("Instruction breakpoint address: %x08", dataAddress);
		} else {
			log_print("Instruction breakpoint failed!");
		}
	}

	return 0;
}

void registerBreakPointHandler() {
	OSSetExceptionCallback((u8) OS_EXCEPTION_DSI, &breakPointHandler);
}

static inline void setDataAddressBreakPointRegister(int address, bool read, bool write) {
	OSSetDABR(1, address, read, write);
}

static inline void setInstructionAddressBreakPointRegister(int address) {
	OSSetIABR(1, address);
}

#endif