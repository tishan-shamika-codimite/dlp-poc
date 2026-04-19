#include "pch.h"
#include "Inflate.h"
#include <cstring>

// ── RFC 1951 deflate decompressor ─────────────────────────────────────────────
// Self-contained implementation — no zlib dependency required.

namespace {

// ── Bit reader ────────────────────────────────────────────────────────────────

struct BitReader {
    const uint8_t* src;
    size_t         srcLen;
    size_t         bytePos = 0;
    uint32_t       buf     = 0;
    int            avail   = 0; // bits available in buf

    bool Ensure(int n) {
        while (avail < n) {
            if (bytePos >= srcLen) return false;
            buf |= static_cast<uint32_t>(src[bytePos++]) << avail;
            avail += 8;
        }
        return true;
    }

    uint32_t Read(int n) {
        if (!Ensure(n)) return 0;
        uint32_t val = buf & ((1u << n) - 1);
        buf >>= n;
        avail -= n;
        return val;
    }

    void AlignToByte() {
        int drop = avail & 7;
        buf >>= drop;
        avail -= drop;
    }
};

// ── Huffman table (max 15-bit codes per deflate spec) ─────────────────────────

struct HuffTable {
    uint16_t counts[16]  = {};
    uint16_t symbols[288] = {};

    void Build(const uint16_t* lengths, int numSymbols) {
        std::memset(counts, 0, sizeof(counts));
        for (int i = 0; i < numSymbols; i++)
            counts[lengths[i]]++;
        counts[0] = 0;

        uint16_t offsets[16];
        offsets[0] = 0;
        for (int i = 1; i < 16; i++)
            offsets[i] = offsets[i - 1] + counts[i - 1];

        for (int i = 0; i < numSymbols; i++)
            if (lengths[i])
                symbols[offsets[lengths[i]]++] = static_cast<uint16_t>(i);
    }

    // Returns decoded symbol or -1 on error
    [[nodiscard]] int Decode(BitReader& br) const {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len <= 15; len++) {
            if (!br.Ensure(1)) return -1;
            code |= (br.buf & 1);
            br.buf >>= 1;
            br.avail--;

            const int cnt = counts[len];
            if (code < first + cnt)
                return symbols[index + (code - first)];

            index += cnt;
            first = (first + cnt) << 1;
            code <<= 1;
        }
        return -1;
    }
};

// ── Static tables from RFC 1951 ──────────────────────────────────────────────

static const uint16_t kLenBase[29] = {
    3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31,
    35,43,51,59, 67,83,99,115, 131,163,195,227, 258
};
static const uint8_t kLenExtra[29] = {
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2,
    3,3,3,3, 4,4,4,4, 5,5,5,5, 0
};
static const uint16_t kDistBase[30] = {
    1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193,
    257,385,513,769, 1025,1537,2049,3073,
    4097,6145,8193,12289, 16385,24577
};
static const uint8_t kDistExtra[30] = {
    0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6,
    7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13
};

// Order in which code-length code lengths appear in dynamic block headers
static const int kCodeLenOrder[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

// ── Block decoders ────────────────────────────────────────────────────────────

static bool DecodeBlock(BitReader& br, const HuffTable& litTable,
                        const HuffTable& distTable, std::string& out) {
    while (true) {
        int sym = litTable.Decode(br);
        if (sym < 0) return false;
        if (sym == 256) return true; // end-of-block

        if (sym < 256) {
            out += static_cast<char>(sym);
            continue;
        }

        // Length code (257..285)
        const int lenIdx = sym - 257;
        if (lenIdx >= 29) return false;
        const int length = kLenBase[lenIdx]
                         + static_cast<int>(br.Read(kLenExtra[lenIdx]));

        // Distance code
        const int distSym = distTable.Decode(br);
        if (distSym < 0 || distSym >= 30) return false;
        const int distance = kDistBase[distSym]
                           + static_cast<int>(br.Read(kDistExtra[distSym]));

        if (distance > static_cast<int>(out.size())) return false;

        // Copy from back-reference (byte-by-byte: overlapping copies are valid)
        const size_t srcPos = out.size() - distance;
        for (int i = 0; i < length; i++)
            out += out[srcPos + i];
    }
}

static void BuildFixedTables(HuffTable& lit, HuffTable& dist) {
    uint16_t lengths[288];
    int i = 0;
    for (; i <= 143; i++) lengths[i] = 8;
    for (; i <= 255; i++) lengths[i] = 9;
    for (; i <= 279; i++) lengths[i] = 7;
    for (; i <= 287; i++) lengths[i] = 8;
    lit.Build(lengths, 288);

    uint16_t dists[30];
    for (i = 0; i < 30; i++) dists[i] = 5;
    dist.Build(dists, 30);
}

static bool ReadDynamicTables(BitReader& br, HuffTable& lit, HuffTable& dist) {
    const int hlit  = static_cast<int>(br.Read(5)) + 257;
    const int hdist = static_cast<int>(br.Read(5)) + 1;
    const int hclen = static_cast<int>(br.Read(4)) + 4;

    // Read code-length code lengths
    uint16_t clLens[19] = {};
    for (int i = 0; i < hclen; i++)
        clLens[kCodeLenOrder[i]] = static_cast<uint16_t>(br.Read(3));

    HuffTable clTable;
    clTable.Build(clLens, 19);

    // Decode literal/length and distance code lengths
    uint16_t lengths[288 + 32] = {};
    const int total = hlit + hdist;
    int idx = 0;

    while (idx < total) {
        int sym = clTable.Decode(br);
        if (sym < 0) return false;

        if (sym < 16) {
            lengths[idx++] = static_cast<uint16_t>(sym);
        } else if (sym == 16) {
            const int rep = static_cast<int>(br.Read(2)) + 3;
            const uint16_t prev = (idx > 0) ? lengths[idx - 1] : 0;
            for (int r = 0; r < rep && idx < total; r++)
                lengths[idx++] = prev;
        } else if (sym == 17) {
            const int rep = static_cast<int>(br.Read(3)) + 3;
            for (int r = 0; r < rep && idx < total; r++)
                lengths[idx++] = 0;
        } else { // sym == 18
            const int rep = static_cast<int>(br.Read(7)) + 11;
            for (int r = 0; r < rep && idx < total; r++)
                lengths[idx++] = 0;
        }
    }

    lit.Build(lengths, hlit);
    dist.Build(lengths + hlit, hdist);
    return true;
}

} // anonymous namespace

// ── Public API ────────────────────────────────────────────────────────────────

std::string InflateRaw(const uint8_t* data, size_t len) {
    BitReader br{data, len};
    std::string output;
    output.reserve(len * 3);

    bool bfinal;
    do {
        bfinal = br.Read(1) != 0;
        const uint32_t btype = br.Read(2);

        if (btype == 0) {
            // ── Uncompressed block ──
            br.AlignToByte();
            if (!br.Ensure(32)) return {};
            const uint16_t blockLen = static_cast<uint16_t>(br.Read(16));
            const uint16_t nlen     = static_cast<uint16_t>(br.Read(16));
            if ((blockLen ^ 0xFFFF) != nlen) return {};

            for (uint16_t i = 0; i < blockLen; i++) {
                if (!br.Ensure(8)) return {};
                output += static_cast<char>(br.Read(8));
            }
        } else if (btype == 1) {
            // ── Fixed Huffman ──
            HuffTable lit, dist;
            BuildFixedTables(lit, dist);
            if (!DecodeBlock(br, lit, dist, output)) return {};

        } else if (btype == 2) {
            // ── Dynamic Huffman ──
            HuffTable lit, dist;
            if (!ReadDynamicTables(br, lit, dist)) return {};
            if (!DecodeBlock(br, lit, dist, output)) return {};

        } else {
            return {}; // invalid block type 3
        }
    } while (!bfinal);

    return output;
}

std::string InflateZlib(const uint8_t* data, size_t len) {
    // Minimum: 2-byte header + 1 byte compressed + 4-byte Adler-32
    if (len < 7) return {};

    const uint8_t cmf = data[0];
    const uint8_t flg = data[1];

    // Header checksum
    if ((cmf * 256 + flg) % 31 != 0) return {};
    // Compression method must be deflate (8)
    if ((cmf & 0x0F) != 8) return {};
    // Preset dictionary flag — not supported
    if (flg & 0x20) return {};

    // Skip 2-byte header; ignore 4-byte Adler-32 trailer
    return InflateRaw(data + 2, len - 6);
}
