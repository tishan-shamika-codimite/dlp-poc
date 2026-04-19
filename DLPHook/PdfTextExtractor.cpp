#include "pch.h"
#include "PdfTextExtractor.h"
#include "Inflate.h"
#include <cstdint>

// ── Helpers ───────────────────────────────────────────────────────────────────

// Extracts text from PDF string literals  (...)  handling nesting and escapes.
static void ExtractPdfStrings(const std::string& data, std::string& out) {
    int depth = 0;
    for (size_t i = 0; i < data.size(); i++) {
        const char c = data[i];

        // Skip escape sequences inside strings
        if (depth > 0 && c == '\\' && i + 1 < data.size()) {
            out += data[i + 1];
            i++; // skip escaped char
            continue;
        }

        if (c == '(') {
            if (depth == 0) out += ' ';
            depth++;
        } else if (c == ')') {
            if (depth > 0) depth--;
            if (depth == 0) out += ' ';
        } else if (depth > 0) {
            out += c;
        }
    }
}

// Extracts the PDF object dictionary that precedes a stream keyword.
// Searches backwards from streamPos for the << ... >> pair.
static std::string FindStreamDict(const std::string& data, size_t streamPos) {
    static constexpr size_t kMaxDictSearch = 4096;
    const size_t searchStart = (streamPos > kMaxDictSearch)
                             ? streamPos - kMaxDictSearch : 0;

    const size_t dictEnd = data.rfind(">>", streamPos);
    if (dictEnd == std::string::npos || dictEnd < searchStart) return {};

    const size_t dictStart = data.rfind("<<", dictEnd);
    if (dictStart == std::string::npos || dictStart < searchStart) return {};

    return data.substr(dictStart, dictEnd - dictStart + 2);
}

// ── Public API ────────────────────────────────────────────────────────────────

bool IsPdfFile(const std::string& rawData) {
    return rawData.size() >= 5
        && rawData[0] == '%'
        && rawData[1] == 'P'
        && rawData[2] == 'D'
        && rawData[3] == 'F'
        && rawData[4] == '-';
}

std::string ExtractTextFromPdf(const std::string& rawData) {
    if (!IsPdfFile(rawData)) return {};

    std::string text;
    text.reserve(rawData.size() / 2);

    // ── Pass 1: string literals in the raw (uncompressed) layer ──────────────
    // Catches metadata, annotations, form field values, and any text in
    // uncompressed content streams.
    ExtractPdfStrings(rawData, text);

    // ── Pass 2: decompress FlateDecode streams and extract their text ────────
    static const std::string kStream    = "stream";
    static const std::string kEndStream = "endstream";

    size_t pos = 0;
    while (pos < rawData.size()) {
        // Locate the next stream body
        const size_t streamKw = rawData.find(kStream, pos);
        if (streamKw == std::string::npos) break;

        // The stream body starts after "stream\r\n" or "stream\n"
        size_t bodyStart = streamKw + kStream.size();
        if (bodyStart < rawData.size() && rawData[bodyStart] == '\r') bodyStart++;
        if (bodyStart < rawData.size() && rawData[bodyStart] == '\n') bodyStart++;

        const size_t endKw = rawData.find(kEndStream, bodyStart);
        if (endKw == std::string::npos) break;

        // Strip optional trailing \r\n before "endstream"
        size_t bodyEnd = endKw;
        if (bodyEnd > bodyStart && rawData[bodyEnd - 1] == '\n') bodyEnd--;
        if (bodyEnd > bodyStart && rawData[bodyEnd - 1] == '\r') bodyEnd--;

        if (bodyEnd > bodyStart) {
            const std::string dict = FindStreamDict(rawData, streamKw);

            std::string decoded;

            if (dict.find("/FlateDecode") != std::string::npos) {
                // Compressed stream — try zlib wrapper first, then raw deflate
                const auto* compressed =
                    reinterpret_cast<const uint8_t*>(&rawData[bodyStart]);
                const size_t compLen = bodyEnd - bodyStart;

                decoded = InflateZlib(compressed, compLen);
                if (decoded.empty())
                    decoded = InflateRaw(compressed, compLen);

            } else if (dict.find("/Filter") == std::string::npos || dict.empty()) {
                // Uncompressed stream (no filter) — use as-is
                decoded = rawData.substr(bodyStart, bodyEnd - bodyStart);
            }
            // Other filters (LZWDecode, ASCII85Decode, etc.) are skipped;
            // they are rare in modern PDFs.

            if (!decoded.empty()) {
                ExtractPdfStrings(decoded, text);
                // Also append raw decompressed bytes so the CC regex can
                // find digit sequences outside of PDF string objects
                text += ' ';
                text += decoded;
            }
        }

        pos = endKw + kEndStream.size();
    }

    return text;
}
