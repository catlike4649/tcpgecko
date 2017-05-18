#ifndef TCPGECKO_KERNEL_H
#define TCPGECKO_KERNEL_H

#include "kernel/syscalls.h"
#include "assertions.h"
#include "dynamic_libs/os_functions.h"

unsigned char *kernelCopyBuffer[4];

void kernelCopy(unsigned char *destinationBuffer, unsigned char *sourceBuffer, unsigned int length) {
	memcpy(kernelCopyBuffer, sourceBuffer, length);
	unsigned int destinationAddress = (unsigned int) OSEffectiveToPhysical(destinationBuffer);
	SC0x25_KernelCopyData(destinationAddress, (unsigned int) &kernelCopyBuffer, length);
	DCFlushRange(destinationBuffer, (u32) length);
}

#define KERNEL_COPY_SOURCE_ADDRESS 0x10100000

int kernelCopyService(int argc, void *argv) {
	while (true) {
		// Read the destination address from the source address
		int destinationAddress = *(int *) KERNEL_COPY_SOURCE_ADDRESS;

		// Avoid crashing
		if (OSIsAddressValid((const void *) destinationAddress)) {
			// Perform memory copy
			unsigned char *valueBuffer = (unsigned char *) (KERNEL_COPY_SOURCE_ADDRESS + 4);
			kernelCopy((unsigned char *) destinationAddress, valueBuffer, 4);

			// "Consume" address and value for synchronization with the code handler for instance
			*(int *) KERNEL_COPY_SOURCE_ADDRESS = 0;
			*(((int *) KERNEL_COPY_SOURCE_ADDRESS) + 1) = 0;
		}
	}
}

void startKernelCopyService() {
	unsigned int stack = (unsigned int) memalign(0x40, 0x100);
	ASSERT_ALLOCATED(stack, "Kernel copy thread stack")
	stack += 0x100;
	void *thread = memalign(0x40, 0x1000);
	ASSERT_ALLOCATED(thread, "Kernel copy thread")

	int status = OSCreateThread(thread, kernelCopyService, 1, NULL, (u32) stack + sizeof(stack), sizeof(stack), 31,
								OS_THREAD_ATTR_AFFINITY_CORE1 | OS_THREAD_ATTR_PINNED_AFFINITY | OS_THREAD_ATTR_DETACH);
	ASSERT_INTEGER(status, 1, "Creating kernel copy thread")
	// OSSetThreadName(thread, "Kernel Copier");
	OSResumeThread(thread);
}

#define MINIMUM_KERNEL_COMPARE_LENGTH 4
#define KERNEL_MEMORY_COMPARE_STEP_SIZE 1

int kernelMemoryCompare(const void *sourceBuffer,
						const void *destinationBuffer,
						int length) {
	if (length < MINIMUM_KERNEL_COMPARE_LENGTH) {
		ASSERT_MINIMUM_HOLDS(length, MINIMUM_KERNEL_COMPARE_LENGTH, "length");
	}

	bool loopEntered = false;

	while (kern_read(sourceBuffer) == kern_read(destinationBuffer)) {
		loopEntered = true;
		sourceBuffer = (char *) sourceBuffer + KERNEL_MEMORY_COMPARE_STEP_SIZE;
		destinationBuffer = (char *) destinationBuffer + KERNEL_MEMORY_COMPARE_STEP_SIZE;
		length -= KERNEL_MEMORY_COMPARE_STEP_SIZE;

		if (length <= MINIMUM_KERNEL_COMPARE_LENGTH - 1) {
			break;
		}
	}

	if (loopEntered) {
		sourceBuffer -= KERNEL_MEMORY_COMPARE_STEP_SIZE;
		destinationBuffer -= KERNEL_MEMORY_COMPARE_STEP_SIZE;
	}

	return kern_read(sourceBuffer) - kern_read(destinationBuffer);
}

#endif