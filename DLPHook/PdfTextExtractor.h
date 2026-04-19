#pragma once
#include <string>

// Returns true if rawData begins with a PDF header (%PDF-).
[[nodiscard]] bool IsPdfFile(const std::string& rawData);

// Extracts readable text from a PDF byte buffer by:
//   1. Collecting PDF string literals  (...)  from the raw bytes
//      (metadata, annotations, form fields, uncompressed text objects).
//   2. Locating stream/endstream blocks, decompressing FlateDecode
//      streams, and extracting text from the decompressed content.
// Returns the concatenated text, or empty string if the data is not a PDF.
[[nodiscard]] std::string ExtractTextFromPdf(const std::string& rawData);
