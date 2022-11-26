/*
author          Oliver Blaser
date            26.11.2022
copyright       GNU GPLv3 - Copyright (c) 2022 Oliver Blaser
*/

#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

#include "util.h"

//#include <omw/omw.h>


namespace
{
    const char* const hexStrDigits = "0123456789ABCDEF";
}

namespace base64_s // static base64 stuff
{
    constexpr size_t base64AlphabetSize = 64;
    const char base64Alphabet[base64AlphabetSize] =
    {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    constexpr size_t base64BlockSize = 3; // 3byte = 24bit = 4 * 6bit
    constexpr size_t base64NChunksPerBlock = 4;
    constexpr size_t base64ChunkNBits = 6;
    constexpr uint32_t base64ChunkMask = 0x3F;

    size_t base64_getAlphInd(char c)
    {
        size_t index = 0;

        while (index < base64_s::base64AlphabetSize)
        {
            if (base64_s::base64Alphabet[index] == c) return index;
            ++index;
        }

        return index;
    }
}



std::string util::toHexStr(uint8_t value)
{
    const char r[] = { hexStrDigits[(value >> 4) & 0x0F], hexStrDigits[value & 0x0F], 0 };
    return r;
}

std::string util::toHexStr(const uint8_t* data, size_t count, char delimiter)
{
    std::string str;

    for (size_t i = 0; i < count; ++i)
    {
        if ((i > 0) && (delimiter != 0)) str += delimiter;

        str += toHexStr(data[i]);
    }

    return str;
}

std::string util::tohexDumpStr(const uint8_t* data, size_t count)
{
    std::string r = "";

    for(size_t i = 0; i < count; ++i)
    {
        if(i > 0)
        {
            if((i % 16) == 0) r += "\n";
            else if ((i % 8) == 0) r += "  ";
            else r += " ";
        }

        r += toHexStr(data[i]);
    }

    return r;
}



int base64::decode(const std::string& encoded, std::vector<uint8_t>& data)
{
    if ((encoded.length() % base64_s::base64NChunksPerBlock) != 0) return base64::INVSTRLEN;

    size_t nNullBytes = 0;

    std::vector<uint8_t> v;
    v.reserve((encoded.length() / base64_s::base64NChunksPerBlock) * base64_s::base64BlockSize);

    for (size_t bi = 0; (bi * base64_s::base64NChunksPerBlock) < encoded.length(); ++bi)
    {
        uint32_t block = 0;

        for (size_t i = 0; i < base64_s::base64NChunksPerBlock; ++i)
        {
            size_t alphInd;

            block <<= base64_s::base64ChunkNBits;

            const char tmpChar = encoded[(bi * base64_s::base64NChunksPerBlock) + i];

            if (tmpChar == '=') ++nNullBytes;
            else
            {
                alphInd = base64_s::base64_getAlphInd(tmpChar);

                if (alphInd < base64_s::base64AlphabetSize) block |= alphInd;
                else return base64::INVCHAR;
            }
        }

        v.push_back((block >> 16) & 0xFF);
        if (nNullBytes < 2) v.push_back((block >> 8) & 0xFF);
        if (nNullBytes < 1) v.push_back(block & 0xFF);
    }

    data = v;

    return base64::OK;
}

void base64::encode(const std::vector<uint8_t>& data, std::string& encoded)
{
    const size_t dataSizeMod = data.size() % base64_s::base64BlockSize;
    const size_t nNullBytes = (dataSizeMod ? base64_s::base64BlockSize - dataSizeMod : 0);
    std::vector<uint8_t> tmpData = data;

    while (tmpData.size() < (data.size() + nNullBytes)) tmpData.push_back(0);

    const size_t nBlocks = tmpData.size() / base64_s::base64BlockSize;
    std::string str = "";

    for (size_t i = 0; i < nBlocks; ++i)
    {
        uint32_t block = ((uint32_t)tmpData[base64_s::base64BlockSize * i + 0] << 16) |
            ((uint32_t)tmpData[base64_s::base64BlockSize * i + 1] << 8) |
            ((uint32_t)tmpData[base64_s::base64BlockSize * i + 2]);

        for (size_t j = 0; j < base64_s::base64NChunksPerBlock; ++j)
        {
            const uint32_t lutIndex = (block & (base64_s::base64ChunkMask << ((base64_s::base64NChunksPerBlock - 1 - j) * base64_s::base64ChunkNBits))) >> ((base64_s::base64NChunksPerBlock - 1 - j) * base64_s::base64ChunkNBits);

            if ((i == (nBlocks - 1)) && (j >= (base64_s::base64NChunksPerBlock - nNullBytes)) && (lutIndex == 0)) str += '=';
            else str += base64_s::base64Alphabet[lutIndex];
        }
    }

    encoded = str;
}

int base64::encode(const uint8_t* data, size_t dataSize, std::string& encoded)
{
    if (!data || !dataSize) return base64::INVSTR;

    base64::encode(std::vector<uint8_t>(data, (data + dataSize)), encoded);

    return base64::OK;
}



size_t tlv::parseLen(const uint8_t* data, size_t* lenSize)
{
    size_t r;
    size_t size = 1;

    if (data[0] & 0x80)
    {
        size += (data[0] & 0x7F);

        r = 0;

        // big endian decode
        for (size_t i = 1; i < size; ++i)
        {
            r <<= 8;
            r |= (size_t)data[i];
        }
    }
    else r = data[0];

    if (lenSize) *lenSize = size;

    return r;
}
