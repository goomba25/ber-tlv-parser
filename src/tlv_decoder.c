#include "tlv_decoder.h"

static uint32_t tlv_parser(uint8_t* buffer, uint32_t length, uint32_t* iterator, TLV_ST* tlv);

static uint32_t tlv_parser(uint8_t* buffer, uint32_t length, uint32_t* iterator, TLV_ST* tlv)
{
    uint32_t result     = SUCCESS;
    uint32_t index      = 0U;
    uint32_t fieldSize  = 0U;
    uint32_t tempLength = 0U;
    uint8_t tempByte    = 0U;

    while (buffer[index] == 0)
    {
        index++;
    }

    /* TAG */
    if (buffer[index] & TAG_DATA_OBJECT_FIRST_BYTE)
    {
        tlv->type = CONSTRUCTED_DATA_OBJECT;
    }

    if ((buffer[index] & TAG_NUMBER_FIRST_BYTE) == TAG_NUMBER_FIRST_BYTE)
    {
        fieldSize = 2U;
    }
    else
    {
        fieldSize = 1U;
    }

    memmove(&tlv->tag, &buffer[index], fieldSize);
    index += fieldSize;

    /* LENGTH */
    tempByte = buffer[index];
    if (tempByte <= LENGTH_SECOND_BYTE)
    {
        memmove(&tlv->length, &buffer[index], 1);
        index++;
    }
    else
    {
        switch (buffer[index])
        {
        case LEGNTH_SECOND_BYTE_ONE:
        case LEGNTH_SECOND_BYTE_TWO:
            fieldSize = tempByte & LENGTH_SECOND_BYTE;
            memmove(&tlv->length, &buffer[index + 1], fieldSize);
            index += (fieldSize + 1);
            break;
        default:
            DEBUG_LOG("Unsupported format in Length field\n");
            result = FAILURE;
            break;
        }

        if (result != SUCCESS)
        {
            goto leave;
        }
    }

    tempLength      = swapEndian32(tlv->length);
    tlv->realLength = tempLength >> (4 - fieldSize) * 8;

    /* VALUE */
    if (tlv->realLength > 0U)
    {
        fieldSize = tlv->realLength;
        while (buffer[index] == 0)
        {
            index++;
            fieldSize--;
        }

        memmove(&tlv->value, &buffer[index], fieldSize);
        tlv->realLength = fieldSize;

        index += fieldSize;
    }
    else
    {
        DEBUG_LOG("TLV realLength is zero.\n");
        result = FAILURE;
        goto leave;
    }

    if (index > length)
    {
        DEBUG_LOG("Invalid buffer length.\n");
        result = FAILURE;
        goto leave;
    }

    *iterator = index;

leave:
    return result;
}

uint32_t tlv_DecodeDsa(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl)
{
    uint32_t result             = SUCCESS;
    uint32_t tempLength         = 0U;
    uint32_t iterator           = 0U;
    uint32_t count              = 0U;
    uint32_t index              = 0U;
    uint8_t temp[DATA_MAX_SIZE] = {
        0U,
    };
    TLV_ST tlvTpl = {
        0U,
    };

    /* Root Sequence */
    result = tlv_parser(key, keyLength, &count, &tlvTpl);
    if (result != SUCCESS)
    {
        DEBUG_LOG("Failed to senc_TlvParser(%08X)\n", result);
        goto leave;
    }

    tempLength = tlvTpl.realLength;
    memmove(temp, &tlvTpl.value, tempLength);

    /* Version */
    if (keyTpl->header.type == KEY_TYPE_DSA_PRIKEY)
    {
        memset(&tlvTpl, 0U, sizeof(TLV_ST));
        result = tlv_parser(temp + iterator, tempLength, &count, &tlvTpl);
        if (result != SUCCESS)
        {
            DEBUG_LOG("Failed to senc_TlvParser(%08X)\n", result);
            goto leave;
        }
        tempLength -= count;
        iterator += count;
    }

    while (tempLength > 0U)
    {
        memset(&tlvTpl, 0U, sizeof(TLV_ST));

        result = tlv_parser(temp + iterator, tempLength, &count, &tlvTpl);
        if (result != SUCCESS)
        {
            DEBUG_LOG("Failed to senc_TlvParser(%08X)\n", result);
            goto leave;
        }

        if (tlvTpl.realLength > 0U)
        {
            keyTpl->attribute[index].dataLength = tlvTpl.realLength;
            memmove(&keyTpl->attribute[index].data, &tlvTpl.value, tlvTpl.realLength);
            index++;
        }

        tempLength -= count;
        iterator += count;
    }

leave:
    return result;
}

uint32_t tlv_DecodeEc(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl)
{
    uint32_t result = SUCCESS;

leave:
    return result;
}

uint32_t tlv_DecodeRsa(uint8_t* key, uint32_t keyLength, KEY_ATTR_ST* keyTpl)
{
    uint32_t result = SUCCESS;

leave:
    return result;
}
