#pragma once
#include <string>

// Encodes/decodes messages using the Chrome Native Messaging protocol:
// 4-byte little-endian length prefix followed by UTF-8 JSON body.

// Write a JSON string to stdout as a native message frame.
void NM_WriteMessage(const std::string& json);

// Read one native message frame from stdin.
// Returns false on EOF or error (extension disconnected / browser closed).
bool NM_ReadMessage(std::string& outJson);
