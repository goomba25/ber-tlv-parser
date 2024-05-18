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

    keyLength = HexStr2Byte(DSA_PRI_KEY, hex);
    DEBUG_LOG("========================== INPUT ==========================\n");
    HEXDUMP(hex, keyLength);
    DEBUG_LOG("===========================================================\n");

    objectTpl.header.type = KEY_TYPE_DSA_PRIKEY;
    result                = tlv_DecodeDsa(hex, keyLength, &objectTpl);
    if (result == SUCCESS)
    {
        for (uint32_t idx = 0U; idx < 10U; idx++)
        {
            HEXDUMP(objectTpl.attribute[idx].data, objectTpl.attribute[idx].dataLength);
        }
    }

exit:
    return 0;
}