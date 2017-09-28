#include "stringify.h"
#include "../dynamic_libs/os_functions.h"
#include "threads.h"
#include "../utils/logger.h"
#include "main.h"
#include "utilities.h"
#include "software_breakpoints.h"

#ifndef TCPGECKO_BREAKPOINTS_H
#define TCPGECKO_BREAKPOINTS_H

// Special purpose registers
#define IABR 0x3F2
#define DABR 0x3F5

// http://www.ds.ewi.tudelft.nl/vakken/in1006/instruction-set/mtspr.html
#define mtspr(spr, value)                        \
    __asm__ __volatile__ ("mtspr %0, %1" : : "K" (spr), "r" (value))    \


// https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.alangref/idalangref_isync_ics_instrs.htm
static inline void isync() {
	__asm__ __volatile__ ("isync" : : : "memory");
}

// https://www.ibm.com/support/knowledgecenter/en/ssw_aix_61/com.ibm.aix.alangref/idalangref_eieio_instrs.htm
static inline void eieio() {
	__asm__ __volatile__ ("eieio" : : : "memory");
}

// https://www.ibm.com/support/knowledgecenter/ssw_aix_71/com.ibm.aix.alangref/idalangref_rfi_retfinter_instrs.htm
static inline void rfi() {
	__asm__ __volatile__ ("rfi" : : : "memory");
}

// https://www.manualslib.com/manual/606065/Ibm-Powerpc-750gx.html?page=64
static inline void setIABR(unsigned int address) {
	mtspr(IABR, address);
	eieio();
	isync();
}

static inline int getIABRAddress() {
	return mfspr(IABR);
}

static inline int getDABRAddress(void *interruptedContext) {
	OSContext *context = (OSContext *) interruptedContext;
	return (int) context->srr0; // Offset 0xA4
}

static inline int getIABRMatch(void *interruptedContext) {
	OSContext *context = (OSContext *) interruptedContext;
	return (int) context->exception_specific1; // Offset 0x98
}

unsigned char breakPointHandler(void *interruptedContext);

void registerBreakPointHandler() {
	log_print("Registering breakpoint handler...\n");
	// TODO Not working, never called?
	// OSSetExceptionCallback((u8) OS_EXCEPTION_DSI, &breakPointHandler);
	// OSSetExceptionCallback((u8) OS_EXCEPTION_ISI, &breakPointHandler);
	// OSSetExceptionCallback((u8) OS_EXCEPTION_PROGRAM, &breakPointHandler);
	OSSetExceptionCallbackEx((u8) OS_EXCEPTION_MODE_GLOBAL_ALL_CORES, (u8) OS_EXCEPTION_PROGRAM, &breakPointHandler);
	// __OSSetInterruptHandler((u8) OS_EXCEPTION_PROGRAM, &breakPointHandler);
	log_print("Breakpoint handler(s) registered!\n");
}

/*void forceDebuggerInitialized() {
	unsigned char patchBytes[] = {0x38, 0x60, 0x00, 0x01};
	patchFunction(OSIsDebuggerInitialized, (char *) patchBytes, sizeof(patchBytes), 0x1C);
}

void forceDebuggerPresent() {
	unsigned char patchBytes[] = {0x38, 0x60, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00};
	patchFunction(OSIsDebuggerPresent, (char *) patchBytes, sizeof(patchBytes), 0x0);
}*/

static inline void setupBreakpointSupport() {
	/*log_print("Clear and enable...\n");
	__OSClearAndEnableInterrupt();
	log_print("Restore...\n");
	OSRestoreInterrupts();
	log_print("Enable...\n");
	OSEnableInterrupts();
	forceDebuggerPresent();
	forceDebuggerInitialized();*/

	registerBreakPointHandler();
}

void setDataBreakpoint(int address, bool read, bool write) {
	setupBreakpointSupport();
	log_print("Setting DABR...\n");
	OSSetDABR(1, address, read, write);
	log_print("DABR set\n");
	int enabled = OSIsInterruptEnabled();
	log_printf("Interrupts enabled: %i\n", enabled);
}

void setInstructionBreakpoint(unsigned int address) {
	setupBreakpointSupport();

	// int returnedAddress;

	log_print("Setting IABR #1...\n");
	// OSSetIABR(1, address);
	setIABR(address);
	log_print("IABR set #1...\n");
	/*
	// TODO Causes crash
	returnedAddress = getIABRAddress();
	log_printf("IABR spr value: %08x\n", returnedAddress);

	log_print("Setting IABR #2...\n");
	setIABR(address);
	log_print("IABR set #2...\n");
	returnedAddress = mfspr(IABR);
	log_printf("IABR spr value: %08x\n", returnedAddress);*/
}

unsigned char breakPointHandler(void *interruptedContext) {
	// Check for data breakpoints
	int dataAddress = getDABRAddress(interruptedContext);
	if (OSIsAddressValid((const void *) dataAddress)) {
		log_printf("Data breakpoint address: %x08\n", dataAddress);
	} else {
		log_printf("Data breakpoint invalid address: %x08\n", dataAddress);

		// Check for instruction breakpoints
		int instructionAddress = getIABRMatch(interruptedContext);
		if (OSIsAddressValid((const void *) instructionAddress)) {
			log_printf("Instruction breakpoint address: %x08\n", dataAddress);
		} else {
			log_print("Instruction breakpoint failed!\n");
		}
	}

	setDataBreakpoint(0, false, false);
	setInstructionBreakpoint(0);

	rfi();

	return 0;
}

#endif