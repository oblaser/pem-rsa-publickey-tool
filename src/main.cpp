/*
author          Oliver Blaser
date            26.11.2022
copyright       GNU GPLv3 - Copyright (c) 2022 Oliver Blaser
*/

// g++ -Wall -std=c++17 -pedantic -o pem-rsa-publickey-tool ../src/main.cpp ../src/middleware/util.cpp
// rm ./pem-rsa-publickey-tool && g++ -Wall -std=c++17 -pedantic -o pem-rsa-publickey-tool ../src/main.cpp ../src/middleware/util.cpp -D_DEBUG && ./pem-rsa-publickey-tool

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

#include "middleware/util.h"


using std::cout;
using std::endl;

namespace
{
    const char* const binName = "pem-rsa-publickey-tool";

    void printHelp()
    {
        cout << "Usage:" << endl;
        cout << "  " << binName << " command [ param1 [param2 [...]]]" << endl;
        cout << endl;
        cout << "Commands:" << endl;
        cout << "  --help" << endl;
        cout << "  extract" << endl;
        cout << "  build" << endl;
    }

    void printError()
    {
        cout << "error" << endl;
        cout << endl;
        printHelp();
    }

    int build(const std::string& mod, const std::string& exp)
    {
        return -1;
    }

    int extract(const std::string& pem)
    {
        int r = 1;

        try
        {
            std::vector<uint8_t> ___data;
            const std::vector<uint8_t>& data = ___data;
            if (base64::decode(pem, ___data) != base64::OK) throw std::runtime_error("PEM - failed to decode base64");

            const uint8_t* const pData = data.data();

            if (data[0] != tlv::tag::sequence) throw std::runtime_error("PEM - not a sequence");

            size_t seqLenSize;
            const size_t seqLen = tlv::parseLen(data.data() + 1, &seqLenSize);
            if (data.size() != (1 + seqLenSize + seqLen)) throw std::runtime_error("PEM - sequence length");

            const size_t intModPos = 1 + seqLenSize;

            if (data[intModPos] != tlv::tag::integer) throw std::runtime_error("PEM - modulus is not an integer");

            size_t intModLenSize;
            const size_t intModLen = tlv::parseLen(data.data() + intModPos + 1, &intModLenSize);
            const size_t modPos = intModPos + 1 + intModLenSize;

            const size_t intExpPos = intModPos + 1 + intModLenSize + intModLen;

            if (data[intExpPos] != tlv::tag::integer) throw std::runtime_error("PEM - exponent is not an integer");

            size_t intExpLenSize;
            const size_t intExpLen = tlv::parseLen(data.data() + intExpPos + 1, &intExpLenSize);
            const size_t expPos = intExpPos + 1 + intExpLenSize;

#if defined(_DEBUG) && 0
            cout << seqLen << " " << intModLenSize << " " << intModLen << " " << intExpLenSize << " " << intExpLen << endl;
            cout << (1 + intModLenSize + intModLen + 1 + intExpLenSize + intExpLen) << endl;
#endif

            if (seqLen != (1 + intModLenSize + intModLen + 1 + intExpLenSize + intExpLen)) throw std::runtime_error("PEM - sequence data length");

            const std::vector<uint8_t> mod(pData + modPos, pData + modPos + intModLen);
            const std::vector<uint8_t> exp(pData + expPos, pData + expPos + intExpLen);

            std::string mod_base64;
            std::string exp_base64;

            base64::encode(mod, mod_base64);
            base64::encode(exp, exp_base64);

            cout << "Modulus:\n" << mod_base64 << endl << util::tohexDumpStr(mod) << endl;
            cout << endl;
            cout << "Exponent:\n" << exp_base64 << endl << util::tohexDumpStr(exp) << endl;

            r = 0;
        }
        catch (const std::exception& ex)
        {
            r = 2;
            cout << "error:    " << ex.what() << endl;
        }

        return r;
    }
}



int main(int argc, char** argv)
{
    int r = -1;

#if defined(_DEBUG)

    //const char* dbg_argv[] = { binName, "--help" };

    const char* dbg_argv[] = { binName, "extract", "MIGJAoGBANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXYUMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dVek9b9VAgMBAAE=" };
    // 30 81 89 02 81 81 00 DC 67 FA F4 9E F2 72 1D 45 2C B4 80 79 06 A0 94 27 50 82 09 DD 67 CE 57 B8 6C 4A 4F 40 9F D2 D1 69 FB 99 5D 85 0C 07 A1 F9 47 1B 56 16 6E F6 7F B9 CF 2A 58 36 37 99 29 AA 4F A8 12 E8 4F C7 82 2B 9D 72 2A 9C DE 6F C2 EE 12 6D CF F0 F2 B8 C4 DD 7C 5C 1A C8 17 51 A9 AC DF 08 22 04 9D 2B D7 F9 4B 09 DE 9A EB 5C 51 1A D8 F8 F9 56 9E F8 FB 37 9B 3F D3 74 65 24 0D FF 34 75 57 A4 F5 BF 55 02 03 01 00 01
    // 00 DC 67 FA F4 9E F2 72 1D 45 2C B4 80 79 06 A0 94 27 50 82 09 DD 67 CE 57 B8 6C 4A 4F 40 9F D2 D1 69 FB 99 5D 85 0C 07 A1 F9 47 1B 56 16 6E F6 7F B9 CF 2A 58 36 37 99 29 AA 4F A8 12 E8 4F C7 82 2B 9D 72 2A 9C DE 6F C2 EE 12 6D CF F0 F2 B8 C4 DD 7C 5C 1A C8 17 51 A9 AC DF 08 22 04 9D 2B D7 F9 4B 09 DE 9A EB 5C 51 1A D8 F8 F9 56 9E F8 FB 37 9B 3F D3 74 65 24 0D FF 34 75 57 A4 F5 BF 55
    // 01 00 01
    // ANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXYUMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dVek9b9V
    // AQAB

    //const char* dbg_argv[] = { binName, "build", "ANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXYUMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dVek9b9V", "AQAB" };

    argc = (sizeof(dbg_argv) / sizeof(dbg_argv[0]));
    argv = (char**)dbg_argv;
    //cout << sizeof(dbg_argv) << "/" << sizeof(dbg_argv[0]) << " = " << argc << endl;
    //for (int i = 0; i < argc; ++i) cout << "  # " << argv[i] << endl;
#endif

    if (argc > 1)
    {
        const std::string cmd = argv[1];

        if (cmd == "--help") printHelp();
        else if (cmd == "extract")
        {
            if (argc == 3) r = extract(argv[2]);
            else cout << binName << " " << cmd << "<PEM_base64>" << endl;
        }
        else if (cmd == "build")
        {
            if (argc == 4) r = build(argv[2], argv[3]);
            else cout << binName << " " << cmd << "<MODULUS_base64> <EXPONENT_base64>" << endl;
        }
        else printError();
    }
    else printError();

#if defined(_DEBUG)
    //cout << omw::foreColor(26) << "===============\nreturn " << r << "\npress enter..." << omw::normal << endl;
    cout << "===============\nreturn " << r << "\npress enter..." << endl;
#if defined(_MSC_VER)
    int dbg___getc_ = getc(stdin);
#endif
#endif

    return r;
}
