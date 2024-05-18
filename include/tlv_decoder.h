#ifndef TLV_DECODER_H
#define TLV_DECODER_H

#include "common.h"
#include "defines.h"

/* TAG MASK */
#define FIRST_SUBSEQUENT_MASK   0b00011111
#define FIRST_DATA_OBJECT_MASK  0b00100000

#define SUBSEQUENT_ANOTHER_BYTE 0b10000000
#define NEXT_LENGTH_BYTE        0b01111111

uint32_t tlv_DecodeDsa(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl);
uint32_t tlv_DecodeEc(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl);
uint32_t tlv_DecodeRsa(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl);

#endif