#include <iosuhax.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "common/common.h"
#include <zlib.h> // Actually must be included before os_functions
#include "dynamic_libs/os_functions.h"
#include <string.h>
#include <malloc.h>
#include "main.h"
#include "dynamic_libs/socket_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "kernel/syscalls.h"
#include "dynamic_libs/fs_functions.h"
#include "utils/logger.h"
#include "system/memory.h"
#include "system/hardware_breakpoints.h"
#include "utils/linked_list.h"
#include "address.h"
#include "system/stack.h"

void *client;
void *commandBlock;
bool kernelCopyServiceStarted;

struct pygecko_bss_t {
	int error, line;
	void *thread;
	unsigned char stack[0x6F00];
};

/* TCP Gecko Commands */
#define COMMAND_WRITE_8 0x01
#define COMMAND_WRITE_16 0x02
#define COMMAND_WRITE_32 0x03
#define COMMAND_READ_MEMORY 0x04
#define COMMAND_READ_MEMORY_KERNEL 0x05
#define COMMAND_VALIDATE_ADDRESS_RANGE 0x06
#define COMMAND_MEMORY_DISASSEMBLE 0x08
#define COMMAND_READ_MEMORY_COMPRESSED 0x09 // TODO Remove command when done and integrate in read memory
#define COMMAND_KERNEL_WRITE 0x0B
#define COMMAND_KERNEL_READ 0x0C
#define COMMAND_TAKE_SCREEN_SHOT 0x0D // TODO Finish this
#define COMMAND_UPLOAD_MEMORY 0x41
#define COMMAND_SERVER_STATUS 0x50
#define COMMAND_GET_DATA_BUFFER_SIZE 0x51
#define COMMAND_READ_FILE 0x52
#define COMMAND_READ_DIRECTORY 0x53
#define COMMAND_REPLACE_FILE 0x54 // TODO Test this
#define COMMAND_GET_CODE_HANDLER_ADDRESS 0x55
#define COMMAND_READ_THREADS 0x56
#define COMMAND_ACCOUNT_IDENTIFIER 0x57
// #define COMMAND_WRITE_SCREEN 0x58 // TODO Exception DSI
#define COMMAND_FOLLOW_POINTER 0x60
#define COMMAND_REMOTE_PROCEDURE_CALL 0x70
#define COMMAND_GET_SYMBOL 0x71
#define COMMAND_MEMORY_SEARCH 0x72
#define COMMAND_ADVANCED_MEMORY_SEARCH 0x73
#define COMMAND_EXECUTE_ASSEMBLY 0x81
#define COMMAND_PAUSE_CONSOLE 0x82
#define COMMAND_RESUME_CONSOLE 0x83
#define COMMAND_IS_CONSOLE_PAUSED 0x84
#define COMMAND_SERVER_VERSION 0x99
#define COMMAND_GET_OS_VERSION 0x9A
#define COMMAND_SET_DATA_BREAKPOINT 0xA0
#define COMMAND_SET_INSTRUCTION_BREAKPOINT 0xA2
#define COMMAND_TOGGLE_BREAKPOINT 0xA5
#define COMMAND_REMOVE_ALL_BREAKPOINTS 0xA6
#define COMMAND_POKE_REGISTERS 0xA7
#define COMMAND_GET_STACK_TRACE 0xA8
#define COMMAND_RUN_KERNEL_COPY_SERVICE 0xCD
#define COMMAND_IOSU_HAX_READ_FILE 0xD0
#define COMMAND_GET_VERSION_HASH 0xE0

#define CHECK_ERROR(cond) if (cond) { bss->line = __LINE__; goto error; }
#define errno (*__gh_errno_ptr())
#define MSG_DONT_WAIT 32
#define EWOULDBLOCK 6
#define DATA_BUFFER_SIZE 0x5000
// #define WRITE_SCREEN_MESSAGE_BUFFER_SIZE 100
#define SERVER_VERSION "05/24/2017"
#define ONLY_ZEROS_READ 0xB0
#define NON_ZEROS_READ 0xBD

#define VERSION_HASH 0x39C9444B

ZEXTERN int ZEXPORT
deflateEnd OF((z_streamp
strm));
ZEXTERN int ZEXPORT
deflateInit OF((z_streamp
strm,
int level
));
ZEXTERN int ZEXPORT
deflate OF((z_streamp
strm,
int flush
));

// ########## Being kernel_copy.h ############

// TODO Variable size, not hard-coded
unsigned char *memcpy_buffer[DATA_BUFFER_SIZE];

void pygecko_memcpy(unsigned char *destinationBuffer, unsigned char *sourceBuffer, unsigned int length) {
	memcpy(memcpy_buffer, sourceBuffer, length);
	SC0x25_KernelCopyData((unsigned int) OSEffectiveToPhysical(destinationBuffer), (unsigned int) &memcpy_buffer,
						  length);
	DCFlushRange(destinationBuffer, (u32) length);
}

// ########## End kernel_copy.h ############

// ########## Being pause.h ############

int (*AVMGetDRCScanMode)(int);

unsigned long getConsoleStatePatchAddress() {
	if (AVMGetDRCScanMode) {
		log_print("Already acquired!\n");
	} else {
		// Acquire the RPL and function
		log_print("Acquiring...\n");
		unsigned int avm_handle;
		OSDynLoad_Acquire("avm.rpl", (u32 *) &avm_handle);
		ASSERT_ALLOCATED(avm_handle, "avm.rpl")
		OSDynLoad_FindExport((u32) avm_handle, 0, "AVMGetDRCScanMode", &AVMGetDRCScanMode);
		ASSERT_ALLOCATED(AVMGetDRCScanMode, "AVMGetDRCScanMode")
		log_print("Acquired!\n");
	}

	return (unsigned long) (AVMGetDRCScanMode + 0x44);
}

typedef enum {
	PAUSED = 0x38000001, RUNNING = 0x38000000
} ConsoleState;

void writeConsoleState(ConsoleState state) {
	// Get the value to write
	int patchValue = state;
	log_printf("Patch value: %x\n", patchValue);

	// Write the value
	unsigned int patchAddress = getConsoleStatePatchAddress();
	log_printf("Patch address: %x\n", patchAddress);
	pygecko_memcpy((unsigned char *) patchAddress, (unsigned char *) &patchValue, 4);
}

bool isConsolePaused() {
	unsigned int patchAddress = getConsoleStatePatchAddress();
	log_printf("Patch address: %x\n", patchAddress);
	int value = *(unsigned int *) patchAddress;

	return value == PAUSED;
}

// ########## End pause.h ############

// ########## Being socket_functions.h ############

static int recvwait(struct pygecko_bss_t *bss, int sock, void *buffer, int len) {
	int ret;
	while (len > 0) {
		ret = recv(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;

	error:
	bss->error = ret;
	return ret;
}

static int recvbyte(struct pygecko_bss_t *bss, int sock) {
	unsigned char buffer[1];
	int ret;

	ret = recvwait(bss, sock, buffer, 1);
	if (ret < 0) return ret;
	return buffer[0];
}

static int checkbyte(int sock) {
	unsigned char buffer[1];
	int ret;

	ret = recv(sock, buffer, 1, MSG_DONT_WAIT);
	if (ret < 0) return ret;
	if (ret == 0) return -1;
	return buffer[0];
}

static int sendwait(struct pygecko_bss_t *bss, int sock, const void *buffer, int len) {
	int ret;
	while (len > 0) {
		ret = send(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;
	error:
	bss->error = ret;
	return ret;
}

static int sendByte(struct pygecko_bss_t *bss, int sock, unsigned char byte) {
	unsigned char buffer[1];

	buffer[0] = byte;
	return sendwait(bss, sock, buffer, 1);
}

void receiveString(struct pygecko_bss_t *bss,
				   int clientfd,
				   char *stringBuffer,
				   int bufferSize) {
	// Receive the string length
	char lengthBuffer[4] = {0};
	int ret = recvwait(bss, clientfd, lengthBuffer, 4);
	ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (string length)")
	int stringLength = ((int *) lengthBuffer)[0];

	if (stringLength >= 0 && stringLength <= bufferSize) {
		// Receive the actual string
		ret = recvwait(bss, clientfd, stringBuffer, stringLength);
		ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (string)")
	} else {
		OSFatal("String buffer size exceeded");
	}
}

// ########## End socket_functions.h ############

/*void writeScreen(char message[100], int secondsDelay) {
	// TODO Does nothing then crashes (in games)?
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);

	OSScreenPutFontEx(0, 14, 1, message);
	OSScreenPutFontEx(1, 14, 1, message);

	sleep(secondsDelay);

	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);
}*/

void considerInitializingFileSystem() {
	if (!client) {
		// Initialize the file system
		int status = FSInit();
		ASSERT_FUNCTION_SUCCEEDED(status, "FSInit")

		// Allocate the client
		client = malloc(FS_CLIENT_SIZE);
		ASSERT_ALLOCATED(client, "Client")

		// Register the client
		status = FSAddClientEx(client, 0, -1);
		ASSERT_FUNCTION_SUCCEEDED(status, "FSAddClientEx")

		// Allocate the command block
		commandBlock = malloc(FS_CMD_BLOCK_SIZE);
		ASSERT_ALLOCATED(commandBlock, "Command block")

		FSInitCmdBlock(commandBlock);
	}
}

#define ERROR_BUFFER_SIZE 150

void reportIllegalCommandByte(int commandByte) {
	char errorBuffer[ERROR_BUFFER_SIZE];
	__os_snprintf(errorBuffer, ERROR_BUFFER_SIZE,
				  "Illegal command byte received: 0x%02x\nServer Version: %s\nIf you see this, you most likely have to update your TCP Gecko Installer.",
				  commandByte, SERVER_VERSION);
	OSFatal(errorBuffer);
}

static int processCommands(struct pygecko_bss_t *bss, int clientfd) {
	int ret;

	// Hold the command and the data
	unsigned char buffer[1 + DATA_BUFFER_SIZE];

	// Run the RPC server
	while (true) {
		ret = checkbyte(clientfd);

		if (ret < 0) {
			CHECK_ERROR(errno != EWOULDBLOCK);
			GX2WaitForVsync();
			continue;
		}

		switch (ret) {
			case COMMAND_WRITE_8: {
				char *destinationAddress;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0);

				destinationAddress = ((char **) buffer)[0];
				*destinationAddress = buffer[7];
				DCFlushRange(destinationAddress, 1);
				break;
			}
			case COMMAND_WRITE_16: {
				short *destinationAddress;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				destinationAddress = ((short **) buffer)[0];
				*destinationAddress = ((short *) buffer)[3];
				DCFlushRange(destinationAddress, 2);
				break;
			}
			case COMMAND_WRITE_32: {
				int destinationAddress, value;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				destinationAddress = ((int *) buffer)[0];
				value = ((int *) buffer)[1];

				pygecko_memcpy((unsigned char *) destinationAddress, (unsigned char *) &value, 4);
				break;
			}
			case COMMAND_READ_MEMORY: {
				const unsigned char *startingAddress, *endingAddress;
				ret = recvwait(bss, clientfd, buffer, 2 * 4);
				CHECK_ERROR(ret < 0)
				startingAddress = ((const unsigned char **) buffer)[0];
				endingAddress = ((const unsigned char **) buffer)[1];

				while (startingAddress != endingAddress) {
					int length = (int) (endingAddress - startingAddress);

					// Do not smash the buffer
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					// Figure out if all bytes are zero to possibly avoid sending them
					int rangeIterationIndex = 0;
					for (; rangeIterationIndex < length; rangeIterationIndex++) {
						int character = startingAddress[rangeIterationIndex];

						if (character != 0) {
							break;
						}
					}

					if (rangeIterationIndex == length) {
						// No need to send all zero bytes for performance
						ret = sendByte(bss, clientfd, ONLY_ZEROS_READ);
						CHECK_ERROR(ret < 0)
					} else {
						// TODO Compression of ptr, sending of status, compressed size and data, length: 1 + 4 + len(data)
						buffer[0] = NON_ZEROS_READ;
						memcpy(buffer + 1, startingAddress, length);
						ret = sendwait(bss, clientfd, buffer, length + 1);
						CHECK_ERROR(ret < 0)
					}

					/* 	No exit condition.
						We reconnect client-sided instead as a hacky work-around
						 to gain a little more performance by avoiding the very rare search canceling
					 */

					startingAddress += length;
				}
				break;
			}
			case COMMAND_READ_MEMORY_KERNEL: {
				const unsigned char *startingAddress, *endingAddress, *useKernRead;
				ret = recvwait(bss, clientfd, buffer, 3 * 4);
				CHECK_ERROR(ret < 0)
				startingAddress = ((const unsigned char **) buffer)[0];
				endingAddress = ((const unsigned char **) buffer)[1];
				useKernRead = ((const unsigned char **) buffer)[2];

				while (startingAddress != endingAddress) {
					int length = (int) (endingAddress - startingAddress);

					// Do not smash the buffer
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					// Figure out if all bytes are zero to possibly avoid sending them
					int rangeIterationIndex = 0;
					for (; rangeIterationIndex < length; rangeIterationIndex++) {
						int character = useKernRead ? kern_read(startingAddress + rangeIterationIndex)
													: startingAddress[rangeIterationIndex];
						if (character != 0) {
							break;
						}
					}

					if (rangeIterationIndex == length) {
						// No need to send all zero bytes for performance
						ret = sendByte(bss, clientfd, ONLY_ZEROS_READ);
						CHECK_ERROR(ret < 0)
					} else {
						buffer[0] = NON_ZEROS_READ;

						if (useKernRead) {
							for (int offset = 0; offset < length; offset += 4) {
								*((int *) (buffer + 1) + offset / 4) = kern_read(startingAddress + offset);
							}
						} else {
							memcpy(buffer + 1, startingAddress, length);
						}

						ret = sendwait(bss, clientfd, buffer, length + 1);
						CHECK_ERROR(ret < 0)
					}

					/* 	No exit condition.
						We reconnect client-sided instead as a hacky work-around
						 to gain a little more performance by avoiding the very rare search canceling
					 */

					startingAddress += length;
				}
				break;
			}
			case COMMAND_VALIDATE_ADDRESS_RANGE: {
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				// Retrieve the data
				int startingAddress = ((int *) buffer)[0];
				int endingAddress = ((int *) buffer)[1];

				int isAddressRangeValid = validateAddressRange(startingAddress, endingAddress);

				sendByte(bss, clientfd, (unsigned char) isAddressRangeValid);
				break;
			}
				/*case COMMAND_DISASSEMBLE_RANGE: {
					// Receive the starting, ending address and the disassembler options
					ret = recvwait(bss, clientfd, buffer, 4 + 4 + 4);
					CHECK_ERROR(ret < 0)
					void *startingAddress = ((void **) buffer)[0];
					void *endingAddress = ((void **) buffer)[1];
					int disassemblerOptions = ((int *) buffer)[2];

					// Disassemble
					DisassemblePPCRange(startingAddress, endingAddress, formatDisassembled, OSGetSymbolName,
										(u32) disassemblerOptions);

					// Send the disassembler buffer size
					int length = DISASSEMBLER_BUFFER_SIZE;
					ret = sendwait(bss, clientfd, &length, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (disassembler buffer size)")

					// Send the data
					ret = sendwait(bss, clientfd, disassemblerBufferPointer, length);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (disassembler buffer)")

					// Place the pointer back to the beginning
					disassemblerBuffer = (char *) disassemblerBufferPointer;

					break;
				}*/
			case COMMAND_MEMORY_DISASSEMBLE: {
				// Receive the starting address, ending address and disassembler options
				ret = recvwait(bss, clientfd, buffer, 4 + 4 + 4);
				CHECK_ERROR(ret < 0)
				int startingAddress = ((int *) buffer)[0];
				int endingAddress = ((int *) buffer)[1];
				int disassemblerOptions = ((int *) buffer)[2];

				int currentAddress = startingAddress;
				int bufferSize = PPC_DISASM_MAX_BUFFER;
				int integerSize = 4;

				// Disassemble everything
				while (currentAddress < endingAddress) {
					int currentIntegerIndex = 0;

					while ((currentIntegerIndex < (DATA_BUFFER_SIZE / integerSize))
						   && (currentAddress < endingAddress)) {
						int value = *(int *) currentAddress;
						((int *) buffer)[currentIntegerIndex++] = value;
						char *opCodeBuffer = malloc(bufferSize);
						bool status = DisassemblePPCOpcode((u32 *) currentAddress, opCodeBuffer, (u32) bufferSize,
														   OSGetSymbolName,
														   (u32) disassemblerOptions);

						((int *) buffer)[currentIntegerIndex++] = status;

						if (status == 1) {
							// Send the length of the opCode buffer string
							int length = strlen(opCodeBuffer);
							((int *) buffer)[currentIntegerIndex++] = length;

							// Send the opCode buffer itself
							memcpy(buffer + (currentIntegerIndex * integerSize), opCodeBuffer, length);
							currentIntegerIndex += (roundUpToAligned(length) / integerSize);
						}

						free(opCodeBuffer);
						currentAddress += integerSize;
					}

					int bytesToSend = currentIntegerIndex * integerSize;
					ret = sendwait(bss, clientfd, &bytesToSend, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (Buffer size)")

					// VALUE(4)|STATUS(4)|LENGTH(4)|DISASSEMBLED(LENGTH)
					ret = sendwait(bss, clientfd, buffer, bytesToSend);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (Buffer)")
				}

				int bytesToSend = 0;
				ret = sendwait(bss, clientfd, &bytesToSend, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (No more bytes)")

				break;
			}
			case COMMAND_READ_MEMORY_COMPRESSED: {
				// Receive the starting address and length
				ret = recvwait(bss, clientfd, buffer, 4 + 4);
				CHECK_ERROR(ret < 0)
				int startingAddress = ((int *) buffer)[0];
				unsigned int inputLength = ((unsigned int *) buffer)[1];

				z_stream stream;
				memset(&stream, 0, sizeof(stream));
				stream.zalloc = Z_NULL;
				stream.zfree = Z_NULL;
				stream.opaque = Z_NULL;

				// Initialize the stream struct
				ret = deflateInit(&stream, Z_BEST_COMPRESSION);
				ASSERT_INTEGER(ret, Z_OK, "deflateInit")

				// Supply the data
				stream.avail_in = inputLength;
				stream.next_in = (Bytef *) startingAddress;
				stream.avail_out = DATA_BUFFER_SIZE;
				void *outputBuffer = (void *) (&buffer + 4);
				stream.next_out = (Bytef *) outputBuffer;

				// Deflate
				ret = deflate(&stream, Z_FINISH);
				ASSERT_INTEGER(ret, Z_OK, "deflate");

				// Finish
				ret = deflateEnd(&stream);
				ASSERT_INTEGER(ret, Z_OK, "deflateEnd");

				// Send the compressed buffer size and content
				int deflatedSize = stream.total_out;
				((int *) buffer)[0] = deflatedSize;
				ret = sendwait(bss, clientfd, buffer, 4 + deflatedSize);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (Compressed data)")

				break;

				// https://www.gamedev.net/resources/_/technical/game-programming/in-memory-data-compression-and-decompression-r2279
				/*

				// Setup compressed buffer
				unsigned int compressedBufferSize = length * 2;
				void *compressedBuffer = (void *) OSAllocFromSystem(compressedBufferSize, 0x4);
				ASSERT_ALLOCATED(compressedBuffer, "Compressed buffer")

				unsigned int zlib_handle;
				OSDynLoad_Acquire("zlib125.rpl", (u32 *) &zlib_handle);
				int (*compress2)(char *, int *, const char *, int, int);
				OSDynLoad_FindExport((u32) zlib_handle, 0, "compress2", &compress2);

				int destinationBufferSize;
				int status = compress2((char *) compressedBuffer, &destinationBufferSize,
									   (const char *) rawBuffer, length, Z_DEFAULT_COMPRESSION);

				ret = sendwait(bss, clientfd, &status, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (status)")

				if (status == Z_OK) {
					// Send the compressed buffer size and content
					((int *) buffer)[0] = destinationBufferSize;
					memcpy(buffer + 4, compressedBuffer, destinationBufferSize);

					ret = sendwait(bss, clientfd, buffer, 4 + destinationBufferSize);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (Compressed data)")
				}

				free(rawBuffer);
				OSFreeToSystem(compressedBuffer);

				break;*/
			}
			case COMMAND_KERNEL_WRITE: {
				void *ptr, *value;
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				ptr = ((void **) buffer)[0];
				value = ((void **) buffer)[1];

				kern_write(ptr, (uint32_t) value);
				break;
			}
			case COMMAND_KERNEL_READ: {
				void *ptr, *value;
				ret = recvwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0);

				ptr = ((void **) buffer)[0];

				value = (void *) kern_read(ptr);

				*(void **) buffer = value;
				sendwait(bss, clientfd, buffer, 4);
				break;
			}
			case COMMAND_TAKE_SCREEN_SHOT: {
				GX2ColorBuffer colorBuffer;
				// TODO Initialize colorBuffer!
				GX2Surface surface = colorBuffer.surface;
				void *image_data = surface.image_data;
				u32 image_size = surface.image_size;

				// Send the image size so that the client knows how much to read
				ret = sendwait(bss, clientfd, &image_size, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (image size)")

				unsigned int imageBytesSent = 0;
				while (imageBytesSent < image_size) {
					int length = image_size - imageBytesSent;

					// Do not smash the buffer
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					// Send the image bytes
					memcpy(buffer, image_data, length);
					ret = sendwait(bss, clientfd, buffer, length);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (image bytes)")

					imageBytesSent += length;
				}

				break;
			}
			case COMMAND_UPLOAD_MEMORY: {
				// Receive the starting and ending addresses
				ret = recvwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)
				unsigned char *current_address = ((unsigned char **) buffer)[0];
				unsigned char *end_address = ((unsigned char **) buffer)[1];

				while (current_address != end_address) {
					int length;

					length = (int) (end_address - current_address);
					if (length > DATA_BUFFER_SIZE) {
						length = DATA_BUFFER_SIZE;
					}

					ret = recvwait(bss, clientfd, buffer, length);
					CHECK_ERROR(ret < 0)
					pygecko_memcpy(current_address, buffer, (unsigned int) length);

					current_address += length;
				}

				break;
			}
			case COMMAND_GET_DATA_BUFFER_SIZE: {
				((int *) buffer)[0] = DATA_BUFFER_SIZE;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0)

				break;
			}
			case COMMAND_READ_FILE: {
				char file_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, file_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				int handle;
				int status = FSOpenFile(client, commandBlock, file_path, "r", &handle, FS_RET_ALL_ERROR);

				if (status == FS_STATUS_OK) {
					// Send the OK status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (OK status)")

					// Retrieve the file statistics
					FSStat stat;
					ret = FSGetStatFile(client, commandBlock, handle, &stat, FS_RET_ALL_ERROR);
					ASSERT_FUNCTION_SUCCEEDED(ret, "FSGetStatFile")

					// Send the total bytes count
					int totalBytes = (int) stat.size;
					((int *) buffer)[0] = totalBytes;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (total bytes)")

					// Allocate the file bytes buffer
					unsigned int file_buffer_size = 0x2000;
					char *fileBuffer = (char *) OSAllocFromSystem(file_buffer_size, FS_IO_BUFFER_ALIGN);
					ASSERT_ALLOCATED(fileBuffer, "File buffer")

					int totalBytesRead = 0;
					while (totalBytesRead < totalBytes) {
						int bytesRead = FSReadFile(client, commandBlock, fileBuffer, 1, file_buffer_size,
												   handle, 0, FS_RET_ALL_ERROR);
						ASSERT_FUNCTION_SUCCEEDED(bytesRead, "FSReadFile")

						// Send file bytes
						ret = sendwait(bss, clientfd, fileBuffer, bytesRead);
						ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (file buffer)")

						totalBytesRead += bytesRead;
					}

					ret = FSCloseFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					ASSERT_FUNCTION_SUCCEEDED(ret, "FSCloseFile")

					OSFreeToSystem(fileBuffer);
				} else {
					// Send the error status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (error status)")
				}

				break;
			}
			case COMMAND_READ_DIRECTORY: {
				char directory_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, directory_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				int handle;
				FSDirEntry entry;

				ret = FSOpenDir(client, commandBlock, directory_path, &handle, FS_RET_ALL_ERROR);

				if (ret == FS_STATUS_OK) {
					// Send the success status
					((int *) buffer)[0] = ret;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (success status)")

					int entrySize = sizeof(FSDirEntry);

					// Read every entry in the given directory
					while (FSReadDir(client, commandBlock, handle, &entry, -1) == FS_STATUS_OK) {
						// Let the client know how much data is going to be sent (even though this is constant)
						((int *) buffer)[0] = entrySize;
						ret = sendwait(bss, clientfd, buffer, 4);
						ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (data coming)")

						// Send the struct
						ret = sendwait(bss, clientfd, &entry, entrySize);
						ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (directory entry)")
					}

					// No more data will be sent, hence a 0 byte
					((int *) buffer)[0] = 0;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (no more data)")

					// Done, close the directory also
					ret = FSCloseDir(client, commandBlock, handle, FS_RET_ALL_ERROR);
					ASSERT_FUNCTION_SUCCEEDED(ret, "FSCloseDir")
				} else {
					// Send the status
					((int *) buffer)[0] = ret;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (error status)")
				}

				break;
			}
			case COMMAND_REPLACE_FILE: {
				// TODO FSOpenFile ACCESS_ERROR

				// Receive the file path
				char file_path[FS_MAX_FULLPATH_SIZE] = {0};
				receiveString(bss, clientfd, file_path, FS_MAX_FULLPATH_SIZE);

				considerInitializingFileSystem();

				// Create an empty file for writing. Its contents will be erased
				int handle;
				int status = FSOpenFile(client, commandBlock, file_path, "w", &handle, FS_RET_ALL_ERROR);

				if (status == FS_STATUS_OK) {
					// Send the OK status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (OK status)")

					// Set the file handle position to the beginning
					ret = FSSetPosFile(client, commandBlock, handle, 0, FS_RET_ALL_ERROR);
					ASSERT_FUNCTION_SUCCEEDED(ret, "FSSetPosFile")

					// Allocate the file bytes buffer
					unsigned int file_buffer_size = 0x2000;
					char *fileBuffer = (char *) OSAllocFromSystem(file_buffer_size, FS_IO_BUFFER_ALIGN);
					ASSERT_ALLOCATED(fileBuffer, "File buffer")

					// Send the maximum file buffer size
					ret = sendwait(bss, clientfd, &file_buffer_size, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (maximum file buffer size)")

					while (true) {
						// Receive the data bytes length
						unsigned int dataLength;
						ret = recvwait(bss, clientfd, &dataLength, 4);
						ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (File bytes length)")
						ASSERT_MAXIMUM_HOLDS(file_buffer_size, dataLength, "File buffer overrun attempted")

						if (dataLength > 0) {
							// Receive the data
							ret = recvwait(bss, clientfd, fileBuffer, dataLength);
							ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (File buffer)")

							// Write the data (and advance file handle position implicitly)
							ret = FSWriteFile(client, commandBlock, fileBuffer, 1,
											  dataLength, handle, 0, FS_RET_ALL_ERROR);
							ASSERT_FUNCTION_SUCCEEDED(ret, "FSWriteFile")
						} else {
							// Done with receiving the new file
							break;
						}
					}

					// Flush the file back
					// ret = FSFlushFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					// CHECK_FUNCTION_FAILED(ret, "FSFlushFile")

					// Close the file
					ret = FSCloseFile(client, commandBlock, handle, FS_RET_ALL_ERROR);
					ASSERT_FUNCTION_SUCCEEDED(ret, "FSCloseFile")

					// Free the file buffer
					OSFreeToSystem(fileBuffer);
				} else {
					// Send the status
					((int *) buffer)[0] = status;
					ret = sendwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (status)")
				}

				break;
			}
			case COMMAND_IOSU_HAX_READ_FILE: {
				log_print("COMMAND_IOSUHAX_READ_FILE");

				// TODO Crashes console on this call
				int returnValue = IOSUHAX_Open(NULL);
				log_print("IOSUHAX_Open Done");
				log_printf("IOSUHAX_Open: %i", returnValue);

				if (returnValue < 0) {
					goto IOSUHAX_OPEN_FAILED;
				}

				int fileSystemFileDescriptor = IOSUHAX_FSA_Open();
				log_printf("IOSUHAX_FSA_Open: %i", fileSystemFileDescriptor);

				if (fileSystemFileDescriptor < 0) {
					goto IOSUHAX_FSA_OPEN_FAILED;
				}

				int fileDescriptor;
				const char *filePath = "/vol/storage_usb/usr/title/0005000e/1010ed00/content/audio/stream/pBGM_GBA_CHEESELAND_F.bfstm";
				returnValue = IOSUHAX_FSA_OpenFile(fileSystemFileDescriptor, filePath, "rb", &fileDescriptor);
				log_printf("IOSUHAX_FSA_OpenFile: %i", returnValue);

				if (returnValue < 0) {
					goto IOSUHAX_OPEN_FILE_FAILED;
				}

				fileStat_s fileStat;
				returnValue = IOSUHAX_FSA_StatFile(fileSystemFileDescriptor, fileDescriptor, &fileStat);
				log_printf("IOSUHAX_FSA_StatFile: %i", returnValue);

				if (returnValue < 0) {
					goto IOSUHAX_READ_FILE_FAILED_CLOSE;
				}

				void *fileBuffer = MEMBucket_alloc(fileStat.size, 4);
				log_printf("File Buffer: %p", fileBuffer);

				if (!fileBuffer) {
					goto IOSUHAX_READ_FILE_FAILED_CLOSE;
				}

				size_t totalBytesRead = 0;
				while (totalBytesRead < fileStat.size) {
					size_t remainingBytes = fileStat.size - totalBytesRead;
					int bytesRead = IOSUHAX_FSA_ReadFile(fileSystemFileDescriptor,
														 fileBuffer + totalBytesRead,
														 0x01,
														 remainingBytes,
														 fileDescriptor,
														 0);
					log_printf("IOSUHAX_FSA_ReadFile: %i", bytesRead);

					if (bytesRead <= 0) {
						goto IOSUHAX_READ_FILE_FAILED_CLOSE;
					} else {
						totalBytesRead += bytesRead;
					}
				}

				log_printf("Bytes read: %i", totalBytesRead);

				IOSUHAX_READ_FILE_FAILED_CLOSE:

				returnValue = IOSUHAX_FSA_CloseFile(fileSystemFileDescriptor, fileDescriptor);
				log_printf("IOSUHAX_FSA_CloseFile: %i", returnValue);

				IOSUHAX_OPEN_FILE_FAILED:

				returnValue = IOSUHAX_FSA_Close(fileSystemFileDescriptor);
				log_printf("IOSUHAX_FSA_Close: %i", returnValue);

				IOSUHAX_FSA_OPEN_FAILED:

				returnValue = IOSUHAX_Close();
				log_printf("IOSUHAX_Close: %i", returnValue);

				IOSUHAX_OPEN_FAILED:

				break;
			}
			case COMMAND_GET_VERSION_HASH: {
				((int *) buffer)[0] = VERSION_HASH;
				ret = sendwait(bss, clientfd, buffer, 4);

				break;
			}
			case COMMAND_GET_CODE_HANDLER_ADDRESS: {
				((int *) buffer)[0] = CODE_HANDLER_INSTALL_ADDRESS;
				ret = sendwait(bss, clientfd, buffer, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (code handler address)")

				break;
			}
			case COMMAND_READ_THREADS: {
				struct node *threads = getAllThreads();
				int threadCount = length(threads);
				log_printf("Thread Count: %i\n", threadCount);

				// Send the thread count
				log_print("Sending thread count...\n");
				((int *) buffer)[0] = threadCount;
				ret = sendwait(bss, clientfd, buffer, sizeof(int));
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (thread count)");

				// Send the thread addresses and data
				struct node *currentThread = threads;
				while (currentThread != NULL) {
					int data = (int) currentThread->data;
					log_printf("Thread data: %08x\n", data);
					((int *) buffer)[0] = (int) currentThread->data;
					memcpy(buffer + sizeof(int), currentThread->data, THREAD_SIZE);
					log_print("Sending node...\n");
					ret = sendwait(bss, clientfd, buffer, sizeof(int) + THREAD_SIZE);
					ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (thread address and data)")

					currentThread = currentThread->next;
				}

				destroy(threads);

				break;
			}
			case COMMAND_ACCOUNT_IDENTIFIER: {
				// Acquire the RPL
				unsigned int nn_act_handle;
				OSDynLoad_Acquire("nn_act.rpl", &nn_act_handle);

				// Acquire the functions via their mangled file names
				int (*nn_act_Initialize)(void);
				OSDynLoad_FindExport(nn_act_handle, 0, "Initialize__Q2_2nn3actFv", &nn_act_Initialize);
				ASSERT_ALLOCATED(nn_act_Initialize, "nn_act_Initialize")
				unsigned char (*nn_act_GetSlotNo)(void);
				OSDynLoad_FindExport(nn_act_handle, 0, "GetSlotNo__Q2_2nn3actFv", &nn_act_GetSlotNo);
				ASSERT_ALLOCATED(nn_act_GetSlotNo, "nn_act_GetSlotNo")
				unsigned int (*nn_act_GetPersistentIdEx)(unsigned char);
				OSDynLoad_FindExport(nn_act_handle, 0, "GetPersistentIdEx__Q2_2nn3actFUc", &nn_act_GetPersistentIdEx);
				ASSERT_ALLOCATED(nn_act_GetPersistentIdEx, "nn_act_GetPersistentIdEx")
				int (*nn_act_Finalize)(void);
				OSDynLoad_FindExport(nn_act_handle, 0, "Finalize__Q2_2nn3actFv", &nn_act_Finalize);
				ASSERT_ALLOCATED(nn_act_Finalize, "nn_act_Finalize")

				// Get the identifier
				ret = nn_act_Initialize();
				// ASSERT_INTEGER(ret, 1, "Initializing account library");
				unsigned char slotNumber = nn_act_GetSlotNo();
				unsigned int persistentIdentifier = nn_act_GetPersistentIdEx(slotNumber);
				ret = nn_act_Finalize();
				ASSERT_FUNCTION_SUCCEEDED(ret, "nn_act_Finalize");

				// Send it
				ret = sendwait(bss, clientfd, &persistentIdentifier, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (persistent identifier)")

				break;
			}
				/*case COMMAND_WRITE_SCREEN: {
					char message[WRITE_SCREEN_MESSAGE_BUFFER_SIZE];
					ret = recvwait(bss, clientfd, buffer, 4);
					ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (write screen seconds)")
					int seconds = ((int *) buffer)[0];
					receiveString(bss, clientfd, message, WRITE_SCREEN_MESSAGE_BUFFER_SIZE);
					writeScreen(message, seconds);

					break;
				}*/
			case COMMAND_FOLLOW_POINTER: {
				ret = recvwait(bss, clientfd, buffer, 8);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (Pointer address and offsets count)")

				// Retrieve the pointer address and amount of offsets
				int baseAddress = ((int *) buffer)[0];
				int offsetsCount = ((int *) buffer)[1];

				// Receive the offsets
				ret = recvwait(bss, clientfd, buffer, offsetsCount * 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (offsets)")
				int offsets[offsetsCount];
				int offsetIndex = 0;
				for (; offsetIndex < offsetsCount; offsetIndex++) {
					offsets[offsetIndex] = ((int *) buffer)[offsetIndex];
				}

				int destinationAddress = baseAddress;
				if (isValidDataAddress(destinationAddress)) {
					// Apply pointer offsets
					for (offsetIndex = 0; offsetIndex < offsetsCount; offsetIndex++) {
						int pointerValue = *(int *) destinationAddress;
						int offset = offsets[offsetIndex];
						destinationAddress = pointerValue + offset;

						// Validate the pointer address
						bool isValidDestinationAddress = isValidDataAddress(destinationAddress);

						// Bail out if invalid
						if (!isValidDestinationAddress) {
							destinationAddress = -1;

							break;
						}
					}
				} else {
					destinationAddress = -1;
				}

				// Return the destination address
				((int *) buffer)[0] = destinationAddress;
				ret = sendwait(bss, clientfd, buffer, 4);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (destination address)")

				break;
			}
			case COMMAND_SERVER_STATUS: {
				ret = sendByte(bss, clientfd, 1);
				CHECK_ERROR(ret < 0)
				break;
			}
			case COMMAND_REMOTE_PROCEDURE_CALL: {
				long long (*fun)(int, int, int, int, int, int, int, int);
				int r3, r4, r5, r6, r7, r8, r9, r10;
				long long result;

				ret = recvwait(bss, clientfd, buffer, 4 + 8 * 4);
				CHECK_ERROR(ret < 0);

				fun = ((void **) buffer)[0];
				r3 = ((int *) buffer)[1];
				r4 = ((int *) buffer)[2];
				r5 = ((int *) buffer)[3];
				r6 = ((int *) buffer)[4];
				r7 = ((int *) buffer)[5];
				r8 = ((int *) buffer)[6];
				r9 = ((int *) buffer)[7];
				r10 = ((int *) buffer)[8];

				result = fun(r3, r4, r5, r6, r7, r8, r9, r10);

				((long long *) buffer)[0] = result;
				ret = sendwait(bss, clientfd, buffer, 8);
				CHECK_ERROR(ret < 0)

				break;
			}
			case COMMAND_GET_SYMBOL: {
				int size = recvbyte(bss, clientfd);
				CHECK_ERROR(size < 0)

				ret = recvwait(bss, clientfd, buffer, size);
				CHECK_ERROR(ret < 0)

				/* Identify the RPL name and symbol name */
				char *rplname = (char *) &((int *) buffer)[2];
				char *symname = (char *) (&buffer[0] + ((int *) buffer)[1]);

				/* Get the symbol and store it in the buffer */
				unsigned int module_handle, function_address;
				OSDynLoad_Acquire(rplname, &module_handle);

				char data = (char) recvbyte(bss, clientfd);
				OSDynLoad_FindExport(module_handle, data, symname, &function_address);

				((int *) buffer)[0] = (int) function_address;
				ret = sendwait(bss, clientfd, buffer, 4);
				CHECK_ERROR(ret < 0)

				break;
			}
			case COMMAND_MEMORY_SEARCH: {
				ret = recvwait(bss, clientfd, buffer, sizeof(int) * 3);
				CHECK_ERROR(ret < 0);
				int address = ((int *) buffer)[0];
				int value = ((int *) buffer)[1];
				int length = ((int *) buffer)[2];
				int index;
				int foundAddress = 0;
				for (index = address; index < address + length; index += sizeof(int)) {
					if (*(int *) index == value) {
						foundAddress = index;
						break;
					}
				}

				((int *) buffer)[0] = foundAddress;
				ret = sendwait(bss, clientfd, buffer, sizeof(int));
				CHECK_ERROR(ret < 0)

				break;
			}
			case COMMAND_ADVANCED_MEMORY_SEARCH: {
				// Receive the initial data
				ret = recvwait(bss, clientfd, buffer, 4 * 6);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (memory search information)")
				int bufferIndex = 0;
				int startingAddress = ((int *) buffer)[bufferIndex++];
				int length = ((int *) buffer)[bufferIndex++];
				int kernelRead = ((int *) buffer)[bufferIndex++];
				int resultsLimit = ((int *) buffer)[bufferIndex++];
				int aligned = ((int *) buffer)[bufferIndex++];
				int searchBytesCount = ((int *) buffer)[bufferIndex];

				// Receive the search bytes
				char searchBytes[searchBytesCount];
				ret = recvwait(bss, clientfd, searchBytes, searchBytesCount);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (memory search bytes)")

				int iterationIncrement = aligned ? searchBytesCount : 1;
				int searchBytesOccurrences = 0;

				// Perform the bytes search and collect the results
				for (int currentAddress = startingAddress;
					 currentAddress < startingAddress + length;
					 currentAddress += iterationIncrement) {

					int comparisonResult;

					if (kernelRead) {
						comparisonResult = kernelMemoryCompare((void *) currentAddress, searchBytes, searchBytesCount);
					} else {
						comparisonResult = memcmp((void *) currentAddress, searchBytes, searchBytesCount);
					}
					if (comparisonResult == 0) {
						// Search bytes have been found
						((int *) buffer)[1 + searchBytesOccurrences] = currentAddress;
						searchBytesOccurrences++;

						if ((resultsLimit == searchBytesOccurrences)
							|| (searchBytesOccurrences == ((DATA_BUFFER_SIZE / 4) - 1))) {
							// We bail out
							break;
						}
					}
				}

				((int *) buffer)[0] = searchBytesOccurrences * 4;
				ret = sendwait(bss, clientfd, buffer, 4 + (searchBytesOccurrences * 4));
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (Sending search bytes occurrences)")

				break;
			}
			case COMMAND_EXECUTE_ASSEMBLY: {
				// Receive the assembly
				receiveString(bss, clientfd, (char *) buffer, DATA_BUFFER_SIZE);

				// Write the assembly to an executable code region
				int destinationAddress = 0x10000000 - DATA_BUFFER_SIZE;
				pygecko_memcpy((unsigned char *) destinationAddress, buffer, DATA_BUFFER_SIZE);

				// Execute the assembly from there
				void (*function)() = (void (*)()) destinationAddress;
				function();

				// Clear the memory contents again
				memset((void *) buffer, 0, DATA_BUFFER_SIZE);
				pygecko_memcpy((unsigned char *) destinationAddress, buffer, DATA_BUFFER_SIZE);

				break;
			}
			case COMMAND_PAUSE_CONSOLE: {
				writeConsoleState(PAUSED);

				break;
			}
			case COMMAND_RESUME_CONSOLE: {
				writeConsoleState(RUNNING);

				break;
			}
			case COMMAND_IS_CONSOLE_PAUSED: {
				bool paused = isConsolePaused();
				log_printf("Paused: %d\n", paused);
				ret = sendByte(bss, clientfd, (unsigned char) paused);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendByte (sending paused console status)")

				break;
			}
			case COMMAND_SERVER_VERSION: {
				char versionBuffer[50];
				strcpy(versionBuffer, SERVER_VERSION);
				int versionLength = strlen(versionBuffer);
				((int *) buffer)[0] = versionLength;
				memcpy(buffer + sizeof(int), versionBuffer, versionLength);

				// Send the length and the version string
				ret = sendwait(bss, clientfd, buffer, sizeof(int) + versionLength);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (server version)");

				break;
			}
			case COMMAND_GET_OS_VERSION: {
				((int *) buffer)[0] = (int) OS_FIRMWARE;
				ret = sendwait(bss, clientfd, buffer, sizeof(int));
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (OS version)");

				break;
			}
			case COMMAND_SET_DATA_BREAKPOINT: {
				// Read the data from the client
				ret = recvwait(bss, clientfd, buffer, sizeof(int) + sizeof(bool) * 2);
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (data breakpoint)");

				// Parse the data and set the breakpoint
				int bufferIndex = 0;
				unsigned int address = ((unsigned int *) buffer)[bufferIndex];
				bufferIndex += sizeof(int);
				bool read = buffer[bufferIndex];
				bufferIndex += sizeof(bool);
				bool write = buffer[bufferIndex];
				bufferIndex += sizeof(bool);
				setDataAddressBreakPointRegister(address, read, write);

				break;
			}
			case COMMAND_SET_INSTRUCTION_BREAKPOINT: {
				// Read the address
				ret = recvwait(bss, clientfd, buffer, sizeof(int));
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (instruction breakpoint)");

				// Parse the address and set the breakpoint
				unsigned int address = ((unsigned int *) buffer)[0];
				setInstructionAddressBreakPointRegister(address);

				break;
			}
			case COMMAND_TOGGLE_BREAKPOINT: {
				// Read the address
				ret = recvwait(bss, clientfd, buffer, sizeof(int));
				ASSERT_FUNCTION_SUCCEEDED(ret, "recvwait (toggle breakpoint)");
				u32 address = ((unsigned int *) buffer)[0];

				struct Breakpoint *breakpoint = getBreakpoint(address, GENERAL_BREAKPOINTS_COUNT);

				if (breakpoint != NULL) {
					breakpoint = removeBreakpoint(breakpoint);
				} else {
					breakpoint = allocateBreakpoint();

					if (breakpoint != NULL) {
						breakpoint = setBreakpoint(breakpoint, address);
					}
				}

				break;
			}
			case COMMAND_REMOVE_ALL_BREAKPOINTS: {
				removeAllBreakpoints();
				break;
			}
			case COMMAND_GET_STACK_TRACE: {
				log_print("Getting stack trace...\n");
				struct node *stackTrace = getStackTrace(NULL);
				int stackTraceLength = length(stackTrace);

				// Let the client know the length beforehand
				int bufferIndex = 0;
				((int *) buffer)[bufferIndex++] = stackTraceLength;

				struct node *currentStackTraceElement = stackTrace;
				while (currentStackTraceElement != NULL) {
					int address = (int) currentStackTraceElement->data;
					log_printf("Stack trace element address: %08x\n", address);
					((int *) buffer)[bufferIndex++] = (int) currentStackTraceElement->data;

					currentStackTraceElement = currentStackTraceElement->next;
				}

				log_printf("Sending stack trace with length %i\n", stackTraceLength);
				ret = sendwait(bss, clientfd, buffer, sizeof(int) + stackTraceLength);
				ASSERT_FUNCTION_SUCCEEDED(ret, "sendwait (stack trace)");

				break;
			}
			case COMMAND_POKE_REGISTERS: {

			}
			case COMMAND_RUN_KERNEL_COPY_SERVICE: {
				if (!kernelCopyServiceStarted) {
					kernelCopyServiceStarted = true;
					startKernelCopyService();
				}

				break;
			}
			default: {
				reportIllegalCommandByte(ret);

				break;
			}
		}
	}

	error:
	bss->error = ret;
	return 0;
}

int sockfd = -1, clientfd = -1, ret = 0, len;
struct sockaddr_in socketAddress;
struct pygecko_bss_t *bss;

static int runTCPGeckoServer(int argc, void *argv) {
	bss = (struct pygecko_bss_t *) argv;

	setup_os_exceptions();
	socket_lib_init();

	log_init(COMPUTER_IP_ADDRESS);

	while (true) {
		socketAddress.sin_family = AF_INET;
		socketAddress.sin_port = 7331;
		socketAddress.sin_addr.s_addr = 0;

		log_printf("socket()...\n");
		sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		CHECK_ERROR(sockfd == -1)

		log_printf("bind()...\n");
		ret = bind(sockfd, (struct sockaddr *) &socketAddress, (s32) 16);
		CHECK_ERROR(ret < 0)

		log_printf("listen()...\n");
		ret = listen(sockfd, (s32) 20);
		CHECK_ERROR(ret < 0)

		while (true) {
			log_printf("accept()...\n");
			len = 16;
			clientfd = accept(sockfd, (struct sockaddr *) &socketAddress, (s32 * ) & len);
			CHECK_ERROR(clientfd == -1)
			log_printf("commands()...\n");
			ret = processCommands(bss, clientfd);
			CHECK_ERROR(ret < 0)
			socketclose(clientfd);
			clientfd = -1;

			log_printf("GX2WaitForVsync() inner...\n");
			GX2WaitForVsync();
		}

		error:
		log_printf("error, closing connection...\n");
		if (clientfd != -1)
			socketclose(clientfd);
		if (sockfd != -1)
			socketclose(sockfd);
		bss->error = ret;

		// Fix the console freezing when e.g. going to the friend list
		log_printf("GX2WaitForVsync() outer...\n");
		GX2WaitForVsync();
	}

	return 0;
}

static int startTCPGeckoThread(int argc, void *argv) {
	log_init(COMPUTER_IP_ADDRESS);
	log_print("Starting TCP Gecko thread...\n");

	// Run the TCP Gecko Installer server
	struct pygecko_bss_t *bss;

	bss = memalign(0x40, sizeof(struct pygecko_bss_t));
	if (bss == 0)
		return 0;
	memset(bss, 0, sizeof(struct pygecko_bss_t));

	if (OSCreateThread(&bss->thread, runTCPGeckoServer, 1, bss, (u32) bss->stack + sizeof(bss->stack),
					   sizeof(bss->stack), 0,
					   0xc) == 1) {
		OSResumeThread(&bss->thread);
	} else {
		free(bss);
	}

	log_print("TCP Gecko thread started...\n");

	// Execute the code handler if it is installed
	if (isCodeHandlerInstalled) {
		log_print("Code handler installed...\n");
		void (*codeHandlerFunction)() = (void (*)()) CODE_HANDLER_INSTALL_ADDRESS;

		while (true) {
			usleep(9000);
			// log_print("Running code handler...\n");
			codeHandlerFunction();
		}
	} else {
		log_print("Code handler not installed...\n");
	}

	return 0;
}

void startTCPGecko() {
	log_init(COMPUTER_IP_ADDRESS);
	log_print("Starting TCP Gecko...\n");

	// Force the debugger to be initialized by default
	// writeInt((unsigned int) (OSIsDebuggerInitialized + 0x1C), 0x38000001); // li r3, 1

	unsigned int stack = (unsigned int) memalign(0x40, 0x100);
	ASSERT_ALLOCATED(stack, "TCP Gecko stack")
	stack += 0x100;
	void *thread = memalign(0x40, 0x1000);
	ASSERT_ALLOCATED(thread, "TCP Gecko thread")

	int status = OSCreateThread(thread, startTCPGeckoThread, 1,
								NULL, (u32) stack + sizeof(stack),
								sizeof(stack), 0,
								OS_THREAD_ATTR_AFFINITY_CORE1 | OS_THREAD_ATTR_PINNED_AFFINITY | OS_THREAD_ATTR_DETACH);
	ASSERT_INTEGER(status, 1, "Creating TCP Gecko thread")
	// OSSetThreadName(thread, "TCP Gecko");
	OSResumeThread(thread);

	log_print("TCP Gecko started...\n");
}