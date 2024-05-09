#include "common.h"

size_t HexStr2Byte(char *hex, char *out)
{
    size_t ret       = -1;
    size_t hexStr_sz = 0;
    char c;
    char val = 0;
    if (!hex || !out)
    {
        return ret;
    }
    hexStr_sz = strlen(hex);

    for (size_t i = 0; i < hexStr_sz; i++)
    {
        c   = hex[i];
        val = 0;
        if (c >= '0' && c <= '9')
        {
            val = (c - '0');
        }
        else if (c >= 'A' && c <= 'F')
        {
            val = (10 + (c - 'A'));
        }
        else if (c >= 'a' && c <= 'f')
        {
            val = (10 + (c - 'a'));
        }
        else
        {
            return ret;
        }

        out[(i / 2)] += val << (((i + 1) % 2) * 4);
    }
    if (hexStr_sz % 2 == 1)
    {
        hexStr_sz++;
    }
    return hexStr_sz / 2;
}

uint16_t swapEndian16(uint16_t num)
{
    // Swap endian (big to little) or (little to big)
    uint16_t b0, b1;
    uint16_t res;

    b0  = (num & 0x00ff) << 8u;
    b1  = (num & 0xff00) >> 8u;

    res = b0 | b1;

    return res;
}

uint32_t swapEndian32(uint32_t num)
{
    // Swap endian (big to little) or (little to big)
    uint32_t b0, b1, b2, b3;
    uint32_t res;

    b0  = (num & 0x000000ff) << 24u;
    b1  = (num & 0x0000ff00) << 8u;
    b2  = (num & 0x00ff0000) >> 8u;
    b3  = (num & 0xff000000) >> 24u;

    res = b0 | b1 | b2 | b3;

    return res;
}

void printTLV(TLV_ST *tlv)
{
    DEBUG_LOG("%02X ", tlv->tag);

    DEBUG_LOG("%02X ", tlv->length);

    if (tlv->type == CONSTRUCTED_DATA_OBJECT)
    {
        DEBUG_LOG("\n\t");
    }
    else
    {
        DEBUG_LOG("\t");
    }

    for (uint32_t idx = 0U; idx < tlv->realLength; idx++)
    {
        DEBUG_LOG("%02x", tlv->value[idx]);
    }

    DEBUG_LOG("\n==========================================\n");
}

void HEXDUMP(uint8_t *B, uint32_t L)
{
    uint32_t addr = 0x00000000U;
    DEBUG_LOG("memory length : %u\n", L);
    DEBUG_LOG("          0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F\n");
    DEBUG_LOG("%08X ", addr);
    for (uint32_t i = 0U; i < L; i++)
    {
        DEBUG_LOG("%02X ", B[i]);
        if ((i & (0x0FU)) == 0x0FU)
        {
            addr += 0x10U;
            if (addr < L)
            {
                DEBUG_LOG("\n%08X ", addr);
            }
        }
    }
    DEBUG_LOG("\n");
}