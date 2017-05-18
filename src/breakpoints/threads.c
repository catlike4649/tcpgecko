#include "threads.h"
#include "linked_list.h"
#include "../dynamic_libs/os_functions.h"

struct node *getAllThreads() {
	struct node *list = NULL;
	int currentThreadAddress = OSGetCurrentThread();
	int iterationThreadAddress = currentThreadAddress;
	int temporaryThreadAddress;

	// Follow "previous thread" pointers back to the beginning
	while ((temporaryThreadAddress = *(int *) (iterationThreadAddress + PREVIOUS_THREAD)) != 0) {
		iterationThreadAddress = temporaryThreadAddress;
	}

	// Now iterate over all threads
	while ((temporaryThreadAddress = *(int *) (iterationThreadAddress + NEXT_THREAD)) != 0) {
		// Grab the thread's address
		insert(list, (void *) iterationThreadAddress);
		iterationThreadAddress = temporaryThreadAddress;
	}

	// The previous while would skip the last thread so add it as well
	insert(list, (void *) iterationThreadAddress);

	return list;
}