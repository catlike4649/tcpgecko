#include <string.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "dynamic_libs/socket_functions.h"
#include "common/common.h"
#include "pygecko.h"
#include "main.h"
#include "utils/logger.h"

#define TITLE_ID_MII_VERSE 0x000500301001600A
#define TITLE_ID_MII_MAKER 0x000500101004A000
#define TITLE_ID_BAYONETTA_2 0x0005000010172500
#define TITLE_ID_INTERNET_BROWSER 0x000500301001200A

bool isRunningTitleID(unsigned long long int japaneseTitleID) {
	unsigned long long int currentTitleID = (unsigned long long int) OSGetTitleID();
	return currentTitleID == japaneseTitleID // JAP
		   || currentTitleID == japaneseTitleID + 0x100 // USA
		   || currentTitleID == japaneseTitleID + 0x200; // EUR
}

int __entry_menu(int argc, char **argv) {
	if (OSGetTitleID != 0
		&& !isRunningTitleID(TITLE_ID_MII_VERSE)
		&& !isRunningTitleID(TITLE_ID_MII_MAKER)
		&& !isRunningTitleID(TITLE_ID_BAYONETTA_2)
		&& !isRunningTitleID(TITLE_ID_INTERNET_BROWSER)) {
		InitOSFunctionPointers();
		InitSocketFunctionPointers();
		InitGX2FunctionPointers();

		log_init(COMPUTER_IP_ADDRESS);
		log_print("OSGetTitleID checks passed...\n");
		startTCPGecko();

		return EXIT_RELAUNCH_ON_LOAD;
	}

	//! *******************************************************************
	//! *                 Jump to our application                    *
	//! *******************************************************************
	return Menu_Main();
}