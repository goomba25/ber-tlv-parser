#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUCCESS           0x00000000U
#define FAILURE           0x00000001U

#define COLOR_RED         "\033[38;2;255;0;0m"
#define COLOR_BLUE        "\033[38;2;0;0;255m"
#define COLOR_GREEN       "\033[38;2;0;255;0m"
#define COLOR_RESET       "\033[0m"

#define KEY_ATTR_MAX_SIZE 10U
#define DATA_MAX_SIZE     4096U

#define DEBUG_LOG         printf

#define trace()           printf("%sTRACE%s %s:%d\n", COLOR_GREEN, COLOR_RESET, __FUNCTION__, __LINE__);

#define CHECK_FUNCTION(x, string)                                                                                    \
    uint32_t retval = (x);                                                                                           \
    if (retval != SUCCESS)                                                                                           \
    {                                                                                                                \
        printf("[%s%s%s:%d]Failed to " string "(%08X) \n ", COLOR_RED, __FUNCTION__, COLOR_RESET, __LINE__, retval); \
        goto exit;                                                                                                   \
    }

#define function_enter() printf("%sENTER%s %s\n", COLOR_BLUE, COLOR_RESET, __FUNCTION__);

#define function_exit()  printf("%sEXIT%s %s\n", COLOR_BLUE, COLOR_RESET, __FUNCTION__);

typedef enum {
    PRIMITIVE_DATA_OBJECT = 0,
    CONSTRUCTED_DATA_OBJECT,
} TLV_DATA_TYPE;

typedef struct {
    uint8_t data[DATA_MAX_SIZE];
    uint32_t dataLength;
} DATA_ST;

typedef struct {
    TLV_DATA_TYPE type;
    uint16_t tag;
    uint32_t length;
    uint32_t realLength;
    uint8_t value[DATA_MAX_SIZE];
} TLV_ST;

typedef struct {
    uint32_t type;
    uint32_t keyType;
} TA_TEMPLATE_HEADER_ST;

typedef struct {
    TA_TEMPLATE_HEADER_ST header;
    DATA_ST attribute[KEY_ATTR_MAX_SIZE];
} KEY_ATTR_ST;

size_t HexStr2Byte(char *hex, char *out);
uint16_t swapEndian16(uint16_t num);
uint32_t swapEndian32(uint32_t num);

void HEXDUMP(uint8_t *B, uint32_t L);

#endif