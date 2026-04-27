#include "JsonMessage.h"
#include <windows.h>
#include <cstdint>
#include <iostream>

// Chrome Native Messaging uses binary stdin/stdout — set both to binary mode.
// On Windows, the CRT translates \n → \r\n in text mode which corrupts the
// 4-byte length prefix. We switch to binary mode once at startup via main().

void NM_WriteMessage(const std::string& json) {
    uint32_t length = static_cast<uint32_t>(json.size());

    // Write 4-byte little-endian length prefix
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, &length, sizeof(length), &written, nullptr);

    // Write JSON body
    WriteFile(hOut, json.c_str(), length, &written, nullptr);
}

bool NM_ReadMessage(std::string& outJson) {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    // Read 4-byte length prefix
    uint32_t length = 0;
    DWORD bytesRead = 0;
    if (!ReadFile(hIn, &length, sizeof(length), &bytesRead, nullptr) || bytesRead != sizeof(length))
        return false;
    if (length == 0 || length > 1024 * 1024)  // sanity cap at 1 MB
        return false;

    // Read JSON body
    outJson.resize(length);
    if (!ReadFile(hIn, &outJson[0], length, &bytesRead, nullptr) || bytesRead != length)
        return false;

    return true;
}
