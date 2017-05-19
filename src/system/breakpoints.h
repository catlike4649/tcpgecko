#include "../utils/stringify.h"
#include "../dynamic_libs/os_functions.h"
#include "threads.h"
#include "exception_handler.h"
#include "../utils/logger.h"
#include "../main.h"
#include "../kernel.h"

#ifndef TCPGECKO_BREAKPOINTS_H
#define TCPGECKO_BREAKPOINTS_H

static inline int getDataAddressBreakpointAddressMatch(void *interruptedContext) {
	OSContext *context = (OSContext *) interruptedContext;
	return (int) context->srr0; // Offset 0xA4
}

static inline int getInstructionBreakpointAddressMatch(void *interruptedContext) {
	OSContext *context = (OSContext *) interruptedContext;
	return (int) context->exception_specific1; // Offset 0x98
}

unsigned char breakPointHandler(void *interruptedContext) {
	log_init(COMPUTER_IP_ADDRESS);

	// Check for data breakpoints
	int dataAddress = getDataAddressBreakpointAddressMatch(interruptedContext);
	if (OSIsAddressValid((const void *) dataAddress)) {
		log_printf("Data breakpoint address: %x08\n", dataAddress);
	} else {
		log_print("Data breakpoint failed!\n");

		// Check for instruction breakpoints
		int instructionAddress = getInstructionBreakpointAddressMatch(interruptedContext);
		if (OSIsAddressValid((const void *) instructionAddress)) {
			log_printf("Instruction breakpoint address: %x08\n", dataAddress);
		} else {
			log_print("Instruction breakpoint failed!\n");
		}
	}

	return 0;
}

void registerBreakPointHandler() {
	log_init(COMPUTER_IP_ADDRESS);
	log_print("Registering breakpoint handler...\n");
	// OSSetExceptionCallback((u8) OS_EXCEPTION_DSI, &breakPointHandler);
	__OSSetInterruptHandler((u8) 0x0, &breakPointHandler);
	log_print("Breakpoint handler registered!\n");
}

void patchFunction(void *function, char *patchBytes, unsigned int patchBytesSize, int functionOffset) {
	log_print("Patching function...\n");
	void *patchAddress = function + functionOffset;
	log_printf("Patch address: %p\n", patchAddress);
	kernelCopy((unsigned char *) patchAddress, (unsigned char *) patchBytes, patchBytesSize);
	log_print("Successfully patched!\n");
}

void forceDebuggerInitialized() {
	unsigned char patchBytes[] = {0x38, 0x60, 0x00, 0x01};
	patchFunction(OSIsDebuggerInitialized, (char *) patchBytes, sizeof(patchBytes), 0x1C);
}

void forceDebuggerPresent() {
	unsigned char patchBytes[] = {0x38, 0x60, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00};
	patchFunction(OSIsDebuggerPresent, (char *) patchBytes, sizeof(patchBytes), 0x0);
}

static inline void setupBreakpointSupport() {
	log_init(COMPUTER_IP_ADDRESS);
	log_print("Clear and enable...\n");
	__OSClearAndEnableInterrupt();
	log_print("Restore...\n");
	OSRestoreInterrupts();
	log_print("Enable...\n");
	OSEnableInterrupts();
	forceDebuggerPresent();
	forceDebuggerInitialized();

	registerBreakPointHandler();
}

static inline void setDataAddressBreakPointRegister(int address, bool read, bool write) {
	setupBreakpointSupport();
	log_init(COMPUTER_IP_ADDRESS);
	log_print("Setting DABR...\n");
	OSSetDABR(1, address, read, write);
	log_print("DABR set\n");
	int enabled = OSIsInterruptEnabled();
	log_printf("Interrupts enabled: %i\n", enabled);
}

static inline void setInstructionAddressBreakPointRegister(int address) {
	setupBreakpointSupport();
	OSSetIABR(1, address);
}

#endif