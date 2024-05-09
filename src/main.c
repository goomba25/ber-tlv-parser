#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "keys.h"
#include "tlv_decoder.h"

int main(void)
{
    uint32_t result         = SUCCESS;
    uint32_t keyLength      = 0U;
    char hex[DATA_MAX_SIZE] = {
        0U,
    };
    KEY_ATTR_ST objectTpl = {
        0U,
    };

    GetDsaKey();

    keyLength = HexStr2Byte(DSA_key[0].data, hex);

    /* TEST */
    result = tlv_GetAttributes(hex, keyLength, &objectTpl);

    for (uint32_t idx = 0U; idx < KEY_ATTR_MAX_SIZE; idx++)
    {
        HEXDUMP(objectTpl.attribute[idx].data, objectTpl.attribute[idx].dataLength);
    }

exit:
    return 0;
}