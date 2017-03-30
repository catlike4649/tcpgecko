#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/fs_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "dynamic_libs/socket_functions.h"
#include "patcher/function_hooks.h"
#include "fs/fs_utils.h"
#include "fs/sd_fat_devoptab.h"
#include "kernel/kernel_functions.h"
#include "system/memory.h"
#include "utils/logger.h"
#include "utils/utils.h"
#include "common/common.h"
#include "main.h"

int CCHandler;

void startMiiMaker() {
	char buf_vol_odd[20];
	snprintf(buf_vol_odd, sizeof(buf_vol_odd), "%s", "/vol/storage_odd03");
	_SYSLaunchTitleByPathFromLauncher(buf_vol_odd, 18, 0);
}

#define PRINT_TEXT2(x, y, ...) { snprintf(messageBuffer, 80, __VA_ARGS__); OSScreenPutFontEx(0, x, y, messageBuffer); OSScreenPutFontEx(1, x, y, messageBuffer); }

#define MAXIMUM_CODE_HANDLER_SIZE 15000
char *codeHandlerBuffer[MAXIMUM_CODE_HANDLER_SIZE];

/* Entry point */
int Menu_Main(void) {
	//!*******************************************************************
	//!                   Initialize function pointers                   *
	//!*******************************************************************
	//! do OS (for acquire) and sockets first so we got logging
	InitOSFunctionPointers();
	InitSocketFunctionPointers();
	InitFSFunctionPointers();
	InitVPadFunctionPointers();
	InitSysFunctionPointers();

	const char ip_address[100] = "192.168.178.49";
	log_init(ip_address);
	log_deinit();
	log_init(ip_address);
	log_printf("Started %s\n", cosAppXmlInfoStruct.rpx_name);

	if (strcasecmp("men.rpx", cosAppXmlInfoStruct.rpx_name) == 0) {
		return EXIT_RELAUNCH_ON_LOAD;
	} else if (strlen(cosAppXmlInfoStruct.rpx_name) > 0 &&
			   strcasecmp("ffl_app.rpx", cosAppXmlInfoStruct.rpx_name) != 0) {

		return EXIT_RELAUNCH_ON_LOAD;
	}

	//! *******************************************************************
	//! *                     Setup EABI registers                        *
	//! *******************************************************************
	register int old_sdata_start, old_sdata2_start;
	asm volatile (
	"mr %0, 13\n"
			"mr %1, 2\n"
			"lis 2, __sdata2_start@h\n"
			"ori 2, 2,__sdata2_start@l\n" // Set the Small Data 2 (Read Only) base register.
			"lis 13, __sdata_start@h\n"
			"ori 13, 13, __sdata_start@l\n"// # Set the Small Data (Read\Write) base register.
	: "=r" (old_sdata_start), "=r" (old_sdata2_start)
	);

	//!*******************************************************************
	//!                    Initialize BSS sections                       *
	//!*******************************************************************
	asm volatile (
	"lis 3, __bss_start@h\n"
			"ori 3, 3,__bss_start@l\n"
			"lis 5, __bss_end@h\n"
			"ori 5, 5, __bss_end@l\n"
			"subf 5, 3, 5\n"
			"li 4, 0\n"
			"bl memset\n"
	);

	SetupKernelCallback();
	PatchMethodHooks();

	memoryInitialize();

	VPADInit();

	// Init screen and screen buffers
	OSScreenInit();
	int screenBuffer0Size = OSScreenGetBufferSizeEx(0);
	int screenBuffer1Size = OSScreenGetBufferSizeEx(1);

	unsigned char *screenBuffer = MEM1_alloc(screenBuffer0Size + screenBuffer1Size, 0x40);

	OSScreenSetBufferEx(0, screenBuffer);
	OSScreenSetBufferEx(1, (screenBuffer + screenBuffer0Size));

	OSScreenEnableEx(0, 1);
	OSScreenEnableEx(1, 1);

	char messageBuffer[80];
	int launchMethod = 0;
	int update_screen = 1;
	int vpadError = -1;
	VPADData vpad_data;

	while (true) {
		VPADRead(0, &vpad_data, 1, &vpadError);

		if (update_screen) {
			OSScreenClearBufferEx(0, 0);
			OSScreenClearBufferEx(1, 0);

			PRINT_TEXT2(14, 1, "-- TCP Gecko Installer --")
			PRINT_TEXT2(0, 5, "Press A to install TCPGecko.")
			PRINT_TEXT2(0, 6, "Press X to install TCPGecko with CosmoCortney's codehandler...")
			PRINT_TEXT2(0, 17, "Press Home to exit ...")

			OSScreenFlipBuffersEx(0);
			OSScreenFlipBuffersEx(1);
		}

		u32 pressedButtons = vpad_data.btns_d | vpad_data.btns_h;

		// Home Button
		if (pressedButtons & VPAD_BUTTON_HOME) {
			launchMethod = 0;
			break;
		}

		// A Button
		if (pressedButtons & VPAD_BUTTON_A) {
			launchMethod = 2;
			break;
		}

		// X Button
		if (pressedButtons & VPAD_BUTTON_X) {
			mount_sd_fat("sd");

			unsigned char *temporaryCodeHandlerBuffer = 0;
			unsigned int codeHandlerSize = 0;
			const char *filePath = "sd:/wiiu/apps/TCPGecko/codehandler.bin";
			int codeHandlerLoaded = LoadFileToMem(filePath, &temporaryCodeHandlerBuffer, &codeHandlerSize);
			if (codeHandlerLoaded == -1) {
				OSScreenClearBufferEx(0, 0);
				OSScreenClearBufferEx(1, 0);
				char codeHandlerNotFoundMessageBuffer[100];
				snprintf(codeHandlerNotFoundMessageBuffer, sizeof(codeHandlerNotFoundMessageBuffer), "%s not found", filePath);
				PRINT_TEXT2(0, 0, codeHandlerNotFoundMessageBuffer)
				OSScreenFlipBuffersEx(0);
				OSScreenFlipBuffersEx(1);
				launchMethod = 0;
				sleep(4);

				break;
			}

			if (codeHandlerSize > MAXIMUM_CODE_HANDLER_SIZE) {
				OSScreenClearBufferEx(0, 0);
				OSScreenClearBufferEx(1, 0);
				PRINT_TEXT2(14, 5, "Codehandler too big");
				OSScreenFlipBuffersEx(0);
				OSScreenFlipBuffersEx(1);
				launchMethod = 0;
				sleep(2);

				break;
			}

			memcpy(codeHandlerBuffer, temporaryCodeHandlerBuffer, codeHandlerSize);
			free(temporaryCodeHandlerBuffer);

			unsigned int physicalCodeHandlerAddress = (unsigned int) OSEffectiveToPhysical(
					(void *) CODE_HANDLER_INSTALL_ADDRESS);
			DCFlushRange(&codeHandlerBuffer, codeHandlerSize);
			SC0x25_KernelCopyData((u32) physicalCodeHandlerAddress, (int) codeHandlerBuffer, codeHandlerSize);
			m_DCInvalidateRange((u32) physicalCodeHandlerAddress, codeHandlerSize);

			unmount_sd_fat("sd");
			CCHandler = 1;

			launchMethod = 2;
			break;
		}

		// Button pressed ?
		update_screen = (pressedButtons & (VPAD_BUTTON_LEFT | VPAD_BUTTON_RIGHT | VPAD_BUTTON_UP | VPAD_BUTTON_DOWN))
						? 1 : 0;
		usleep(20 * 1000);
	}

	asm volatile ("mr 13, %0" : : "r" (old_sdata_start));
	asm volatile ("mr 2,  %0" : : "r" (old_sdata2_start));

	MEM1_free(screenBuffer);
	screenBuffer = NULL;

	log_deinit();

	memoryRelease();

	if (launchMethod == 0) {
		RestoreInstructions();
		return EXIT_SUCCESS;
	} else if (launchMethod == 1) {
		startMiiMaker();
	} else {
		SYSLaunchMenu();
	}

	return EXIT_RELAUNCH_ON_LOAD;
}