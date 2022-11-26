/*
author          Oliver Blaser
date            26.11.2022
copyright       GNU GPLv3 - Copyright (c) 2022 Oliver Blaser
*/

#ifndef IG_MDW_UTIL_H
#define IG_MDW_UTIL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace util
{
    constexpr char toHexStr_defaultDelimiter = 0x20;
    std::string toHexStr(uint8_t value);
    std::string toHexStr(const uint8_t* data, size_t count, char delimiter = toHexStr_defaultDelimiter);
    inline std::string toHexStr(const std::vector<uint8_t>& data, char delimiter = toHexStr_defaultDelimiter) { return toHexStr(data.data(), data.size(), delimiter); }

    std::string tohexDumpStr(const uint8_t* data, size_t count);
    inline std::string tohexDumpStr(const std::vector<uint8_t>& data) { return tohexDumpStr(data.data(), data.size()); }
}

namespace base64
{
    constexpr int OK = 0;
    constexpr int INVSTR = 1;
    constexpr int INVSTRLEN = 2;
    constexpr int INVCHAR = 3;

    int decode(const std::string& encoded, std::vector<uint8_t>& data);
    void encode(const std::vector<uint8_t>& data, std::string& encoded);
    int encode(const uint8_t* data, size_t dataSize, std::string& encoded);
}

namespace tlv
{
    namespace tag
    {
        constexpr uint8_t sequence = 0x30;
        constexpr uint8_t integer = 0x02;
    }

    size_t parseLen(const uint8_t* data, size_t* lenSize = nullptr);
}

#endif // IG_MDW_UTIL_H
