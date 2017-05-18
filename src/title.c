#include "dynamic_libs/os_functions.h"

bool isRunningTitleID(unsigned long long int japaneseTitleID) {
	unsigned long long int currentTitleID = (unsigned long long int) OSGetTitleID();
	return currentTitleID == japaneseTitleID // JAP
		   || currentTitleID == japaneseTitleID + 0x100 // USA
		   || currentTitleID == japaneseTitleID + 0x200; // EUR
}