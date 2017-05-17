#include "bit.h"
#include "stringify.h"

#ifndef TCPGECKO_BREAKPOINTS_H
#define TCPGECKO_BREAKPOINTS_H

/* Breakpoint types
#define BREAKPOINT_READ 0x01
#define BREAKPOINT_WRITE 0x02 */

struct DataBreakpoint {
	unsigned int value;
	bool translate;
	bool write;
	bool read;
} __attribute__((packed));

// Special purpose registers
#define INSTRUCTION_ADDRESS_BREAKPOINT_REGISTER 0x3F2
#define DATA_ADDRESS_BREAKPOINT_REGISTER 0x3F5

// Data address breakpoint bit indices
#define TRANSLATE_BIT_INDEX 29
#define WRITE_BIT_INDEX 30
#define READ_BIT_INDEX 31

// http://www.ds.ewi.tudelft.nl/vakken/in1006/instruction-set/mtspr.html
#define moveToSpecialPurposeRegister(specialPurposeRegister, value)                            \
    __asm__ __volatile__ ("mtspr %0, %1" : : "K" (specialPurposeRegister), "r" (value))    \

// http://elixir.free-electrons.com/linux/v2.6.24/source/include/asm-powerpc/reg.h#L713
#define moveFromSpecialPurposeRegister(specialPurposeRegister)                    \
({unsigned int value;                                                            \
asm volatile("mfspr %0, " __stringify(specialPurposeRegister) : "=r" (value));    \
value;})                                                                        \


// https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.alangref/idalangref_isync_ics_instrs.htm
static inline void synchronizeInstructions() {
	__asm__ __volatile__ ("isync" : : : "memory");
}

// https://www.ibm.com/support/knowledgecenter/en/ssw_aix_61/com.ibm.aix.alangref/idalangref_eieio_instrs.htm
static inline void enforeInOrderExecutionOfIO() {
	__asm__ __volatile__ ("eieio" : : : "memory");
}

static inline void setDataAddressBreakpointRegister(struct DataBreakpoint dataBreakpoint) {
	unsigned int value = dataBreakpoint.value;

	// Breakpoint translation
	value = setBit(value, dataBreakpoint.translate, TRANSLATE_BIT_INDEX);

	// Write breakpoint
	value = setBit(value, dataBreakpoint.write, WRITE_BIT_INDEX);

	// Read breakpoint
	value = setBit(value, dataBreakpoint.read, READ_BIT_INDEX);

	moveToSpecialPurposeRegister(DATA_ADDRESS_BREAKPOINT_REGISTER, value);
	synchronizeInstructions();
}

static inline struct DataBreakpoint getDataAddressBreakpointRegisterContents(struct DataBreakpoint dataBreakpoint) {
	unsigned int value = moveFromSpecialPurposeRegister(DATA_ADDRESS_BREAKPOINT_REGISTER);
	dataBreakpoint.translate = getBit(value, TRANSLATE_BIT_INDEX);
	dataBreakpoint.write = getBit(value, WRITE_BIT_INDEX);
	dataBreakpoint.read = getBit(value, READ_BIT_INDEX);
	value = setBit(value, 0, TRANSLATE_BIT_INDEX);
	value = setBit(value, 0, WRITE_BIT_INDEX);
	value = setBit(value, 0, READ_BIT_INDEX);
	dataBreakpoint.value = value;

	return dataBreakpoint;
}

// https://www.manualslib.com/manual/606065/Ibm-Powerpc-750gx.html?page=64
static inline void setInstructionAddressBreakpointRegister(unsigned int address) {
	moveToSpecialPurposeRegister(INSTRUCTION_ADDRESS_BREAKPOINT_REGISTER, address);
	synchronizeInstructions();
}

static inline int getInstructionAddressBreakpointRegister() {
	return moveFromSpecialPurposeRegister(INSTRUCTION_ADDRESS_BREAKPOINT_REGISTER);
}

#endif