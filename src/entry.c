#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "dynamic_libs/socket_functions.h"
#include "common/common.h"
#include "pygecko.h"
#include "main.h"
#include "utils/logger.h"
#include "title.h"

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