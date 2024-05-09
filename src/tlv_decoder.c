#include "tlv_decoder.h"

uint32_t tlv_GetTLVData(uint8_t* key, uint32_t keyLength, TLV_ST* tlv, uint32_t* count)
{
    uint32_t result     = SUCCESS;
    uint32_t index      = 0U;
    size_t fieldSize    = 0U;
    uint8_t tempByte    = 0;
    uint32_t tempLength = 0U;

    while (key[index] == 0)
    {
        index++;
    }

    /* TAG */
    if (key[index] & FIRST_DATA_OBJECT_MASK)
    {
        tlv->type = CONSTRUCTED_DATA_OBJECT;
    }
    else
    {
        tlv->type = PRIMITIVE_DATA_OBJECT;
    }

    if ((key[index] & FIRST_SUBSEQUENT_MASK) == FIRST_SUBSEQUENT_MASK)
    {
        fieldSize = 2;
    }
    else
    {
        fieldSize = 1;
    }

    (void)memcpy(&tlv->tag, &key[index], fieldSize);
    index += fieldSize;

    /* LENGTH */
    tempByte = key[index];
    if (tempByte <= NEXT_LENGTH_BYTE)
    {
        (void)memcpy(&tlv->length, &key[index], 1);
        index++;
    }
    else
    {
        switch (key[index])
        {
        case 0x81:
        case 0x82:
            fieldSize = tempByte & NEXT_LENGTH_BYTE;
            memcpy(&tlv->length, &key[index + 1], fieldSize);
            index += (fieldSize + 1);
            break;
        default:
            DEBUG_LOG("Unsupported format in Length field");
            break;
        }
    }

    tempLength      = swapEndian32(tlv->length);
    tlv->realLength = tempLength >> (4 - fieldSize) * 8;

    /* VALUE */
    if (tlv->realLength > 0U)
    {
        fieldSize = tlv->realLength;
        (void)memcpy(&tlv->value, &key[index], fieldSize);

        index += fieldSize;
    }
    else
    {
        DEBUG_LOG("TLV realLength is zero\n");
        return FAILURE;
    }

    *count = index;

    return result;
}

uint32_t tlv_GetAttributes(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* attrs)
{
    uint32_t result = SUCCESS;
    TLV_ST tlv      = {
        0U,
    };
    uint8_t temp[4096U] = {
        0U,
    };
    uint32_t tempLength = 0U;
    uint32_t iterator   = 0U;
    uint32_t count      = 0U;
    uint32_t index      = 0U;

    result              = tlv_GetTLVData(key, keyLength, &tlv, &count);
    if (result == SUCCESS)
    {
        printTLV(&tlv);
    }
    else
    {
        return FAILURE;
    }

    if (tlv.type == CONSTRUCTED_DATA_OBJECT)
    {
        tempLength = tlv.realLength;
        (void)memcpy(temp, &tlv.value, tempLength);

        while (tempLength > 0)
        {
            (void)memset(&tlv, 0U, sizeof(TLV_ST));

            result = tlv_GetTLVData(temp + iterator, tempLength, &tlv, &count);
            if (result == SUCCESS)
            {
                attrs->attribute[index].dataLength = tlv.realLength;
                (void)memcpy(&attrs->attribute[index].data, &tlv.value, tlv.realLength);

                printTLV(&tlv);
                tempLength -= count;
                iterator += count;
                index++;
            }
            else
            {
                return FAILURE;
            }
        }
    }

    return result;
}