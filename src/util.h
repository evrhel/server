#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

// convert data to hex string
//
// Parameters:
// - data: data to convert
// - len: length of data
//
// Return:
// A hex string
char *tohex(uint8_t *data, int len);

// convert hex string to data
//
// Parameters:
// - str: hex string
// - data: data to store
// - len: maximum length of data
void fromhex(const char *str, uint8_t *data, int len);

#endif
