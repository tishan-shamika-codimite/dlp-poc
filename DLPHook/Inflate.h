#pragma once
#include <string>
#include <cstdint>

// Decompresses raw deflate data (RFC 1951).
// Returns decompressed bytes, or empty string on failure.
[[nodiscard]] std::string InflateRaw(const uint8_t* data, size_t len);

// Decompresses zlib-wrapped data (RFC 1950): strips the 2-byte header
// and 4-byte Adler-32 trailer, then inflates the inner deflate stream.
[[nodiscard]] std::string InflateZlib(const uint8_t* data, size_t len);
