#ifndef TCPGECKO_BIT_H
#define TCPGECKO_BIT_H

// http://stackoverflow.com/a/47990/3764804
inline unsigned int setBit(unsigned int value, bool bit, int bitIndex) {
	return value | (bit << bitIndex);
}

inline bool getBit(unsigned int value, int bitIndex) {
	return ((value >> bitIndex) & 1) == 1;
}

#endif