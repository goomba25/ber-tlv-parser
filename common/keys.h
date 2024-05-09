#ifndef KEYS_H
#define KEYS_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    char* P;
    char* Q;
    char* G;
    char* X;
    char* Y;
} DSA_KEY_ATTR;

typedef struct {
    char* data;
} DSA_KEY_VALUE;

DSA_KEY_ATTR* DSA_attr;
DSA_KEY_VALUE DSA_key[2];

void GetDsaPublicKeyAttr(void)
{
    DSA_attr->P =
        "aa9a0d6116807cf74e0ee63cdc6f38110f873affc6db2d9ad854ae27a384230dd904f8"
        "a6ceb11bb2983973c0d819ccf02df04d82cc7926d61be78f5ad92a05b9308aca5a9ecd"
        "7461fc1b51da3e9d849fce5075d9c027f1afeb0ab7916df4a7b72b3bb00461f4354231"
        "3c8b82354f88c542a48bfa73bcc1db4ffed329b2cc5cff";
    DSA_attr->Q = "f780e706db7e465dd0eeec3f1b929240157f476f";
    DSA_attr->G =
        "3b80103191e0b2d6b949e1dbfb621c5c8fb45bb9f9db5a52372728045015b56975b56b"
        "3f8b97659600194442d075a8c5c8c1588ee01d848e7b42905edda807209e1395a130cf"
        "7fb2630c2bfcf46cc2f8cdc2e0a11eed9189b35d92b2619daff95ac18b0c0e2fd1c8e4"
        "49e225f812b29815efd1d05d7bc1bf6efaa1766ec2a322";
    DSA_attr->X = "";
    DSA_attr->Y =
        "4029a121f6627127bc8aeb97bfeec2a80b0800ed015a91bcf39869187535e91b5db53e"
        "e840056529c1e4ccdbc21e64b813cc3d2c170c6030a0d195645bd3657256647bafc062"
        "3944e44f1c5f7c50318182e68966b9a16f46da9e343301db694d8f3b62052b66dae252"
        "22c53125a7893416994055a0284393f67c6b2e3bbf0cd4";
}

void GetDsaPrivateKeyAttr(void)
{
    DSA_attr->P =
        "aa9a0d6116807cf74e0ee63cdc6f38110f873affc6db2d9ad854ae27a384230dd904f8"
        "a6ceb11bb2983973c0d819ccf02df04d82cc7926d61be78f5ad92a05b9308aca5a9ecd"
        "7461fc1b51da3e9d849fce5075d9c027f1afeb0ab7916df4a7b72b3bb00461f4354231"
        "3c8b82354f88c542a48bfa73bcc1db4ffed329b2cc5cff";
    DSA_attr->Q = "f780e706db7e465dd0eeec3f1b929240157f476f";
    DSA_attr->G =
        "3b80103191e0b2d6b949e1dbfb621c5c8fb45bb9f9db5a52372728045015b56975b56b"
        "3f8b97659600194442d075a8c5c8c1588ee01d848e7b42905edda807209e1395a130cf"
        "7fb2630c2bfcf46cc2f8cdc2e0a11eed9189b35d92b2619daff95ac18b0c0e2fd1c8e4"
        "49e225f812b29815efd1d05d7bc1bf6efaa1766ec2a322";
    DSA_attr->X = "0ef58b26a800a7bf0aabe5d795acaff5a8c88be5";
    DSA_attr->Y =
        "4029a121f6627127bc8aeb97bfeec2a80b0800ed015a91bcf39869187535e91b5db53e"
        "e840056529c1e4ccdbc21e64b813cc3d2c170c6030a0d195645bd3657256647bafc062"
        "3944e44f1c5f7c50318182e68966b9a16f46da9e343301db694d8f3b62052b66dae252"
        "22c53125a7893416994055a0284393f67c6b2e3bbf0cd4";
}

void GetDsaKey()
{
    DSA_key[0].data =
        "308201A10281804029A121F6627127BC8AEB97BFEEC2A80B0800ED015A91BCF3986918"
        "7535E91B5DB53EE840056529C1E4CCDBC21E64B813CC3D2C170C6030A0D195645BD365"
        "7256647BAFC0623944E44F1C5F7C50318182E68966B9A16F46DA9E343301DB694D8F3B"
        "62052B66DAE25222C53125A7893416994055A0284393F67C6B2E3BBF0CD402818100AA"
        "9A0D6116807CF74E0EE63CDC6F38110F873AFFC6DB2D9AD854AE27A384230DD904F8A6"
        "CEB11BB2983973C0D819CCF02DF04D82CC7926D61BE78F5AD92A05B9308ACA5A9ECD74"
        "61FC1B51DA3E9D849FCE5075D9C027F1AFEB0AB7916DF4A7B72B3BB00461F43542313C"
        "8B82354F88C542A48BFA73BCC1DB4FFED329B2CC5CFF021500F780E706DB7E465DD0EE"
        "EC3F1B929240157F476F0281803B80103191E0B2D6B949E1DBFB621C5C8FB45BB9F9DB"
        "5A52372728045015B56975B56B3F8B97659600194442D075A8C5C8C1588EE01D848E7B"
        "42905EDDA807209E1395A130CF7FB2630C2BFCF46CC2F8CDC2E0A11EED9189B35D92B2"
        "619DAFF95AC18B0C0E2FD1C8E449E225F812B29815EFD1D05D7BC1BF6EFAA1766EC2A3"
        "22";
}

#endif