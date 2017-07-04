#ifndef TCPGECKO_UTILITIES_H
#define TCPGECKO_UTILITIES_H

#include "../dynamic_libs/os_functions.h"
#include "../utils/logger.h"
#include "kernel.h"
#include "../common/kernel_types.h"

void writeCode(u32 address, u32 instruction) {
	u32 *pointer = (u32 *) (address + 0xA0000000);
	*pointer = instruction;
	DCFlushRange(pointer, 4);
	ICInvalidateRange(pointer, 4);
}

void patchFunction(char *function, char *patchBytes, unsigned int patchBytesSize, int functionOffset) {
	log_print("Patching function...\n");
	void *patchAddress = function + functionOffset;
	log_printf("Patch address: %p\n", patchAddress);
	kernelCopyInt((unsigned char *) patchAddress, (unsigned char *) patchBytes, patchBytesSize);
	log_print("Successfully patched!\n");
}

#endif