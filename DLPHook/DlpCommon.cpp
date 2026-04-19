#include "pch.h"
#include "DlpCommon.h"
#include <regex>
#include <atomic>
#include <functional>
#include <memory>

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Validators
// ════════════════════════════════════════════════════════════════════════════

// ── Luhn algorithm ────────────────────────────────────────────────────────────
static bool LuhnCheck(const std::string& digits) {
    const size_t len = digits.size();
    if (len < 13 || len > 19) return false;

    int  sum       = 0;
    bool alternate = false;
    for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
        if (!isdigit(static_cast<unsigned char>(digits[i]))) return false;
        int n = digits[i] - '0';
        if (alternate) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
        alternate = !alternate;
    }
    return (sum % 10) == 0;
}

// Strips spaces and dashes from a regex match, then runs Luhn check.
static bool ValidateCreditCard(const std::string& matchStr) {
    std::string digits;
    digits.reserve(19);
    for (char c : matchStr)
        if (isdigit(static_cast<unsigned char>(c))) digits += c;
    return LuhnCheck(digits);
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Pattern registration table
// ════════════════════════════════════════════════════════════════════════════
//
//  Each PatternEntry maps a std::regex to a DLP category.  The optional
//  `validate` function receives the full regex match string and returns false
//  to reject the match (e.g. Luhn check for credit cards).
//
//  Patterns within the same category are evaluated in order; the first one
//  that fires (and passes validation) produces a DlpMatch for that category.
//  Subsequent patterns in the same category are then skipped.
//

struct PatternEntry {
    DlpCategory     category;
    const wchar_t*  patternName;
    const wchar_t*  categoryLabel;
    std::regex      re;
    std::function<bool(const std::string&)> validate; // nullptr = presence is enough
};

static const std::vector<PatternEntry>& GetPatterns() {
    // C++11 magic-static — zero-overhead after the first call, thread-safe init.
    static const std::vector<PatternEntry> kPatterns = {

        // ── PCI: Payment & Cardholder Data ───────────────────────────────────
        // Covers the three data elements that together constitute a full card
        // record under PCI-DSS: PAN (primary account number), CVV/CVC security
        // code, and expiration date.

        {
            DlpCategory::PCI,
            L"Credit Card Number",
            L"Payment card data (PCI)",
            // 13–19 digit sequence with optional space/dash separators
            std::regex(R"(\b(?:\d[ \-]?){12,18}\d\b)"),
            ValidateCreditCard   // Luhn check eliminates random digit strings
        },
        {
            DlpCategory::PCI,
            L"Card CVV / CVC Security Code",
            L"Payment card data (PCI)",
            // Must be preceded by a card-security keyword to avoid matching
            // any stand-alone 3-digit number (e.g. page numbers, quantities)
            std::regex(
                R"((?:cvv2?|cvc2?|cid|security\s+code)\s*[:\-]?\s*\b\d{3,4}\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::PCI,
            L"Card Expiration Date",
            L"Payment card data (PCI)",
            // MM/YY or MM/YYYY after an expiry keyword
            std::regex(
                R"((?:exp(?:ir(?:y|ation)?)?|valid\s+(?:thru?|through)|card\s+exp)\s*[:\-]?\s*(?:0[1-9]|1[0-2])\s*[/\-]\s*\d{2,4}\b)",
                std::regex_constants::icase),
            nullptr
        },

        // ── PII: Individual Identity ──────────────────────────────────────────
        // US Social Security Numbers in formatted (XXX-XX-XXXX) form.
        // Formatted SSNs are distinct enough to match without keyword context;
        // the exclusion rules (000/666/9xx prefixes, 00 middle, 0000 suffix)
        // remove a significant portion of false positives.
        //
        // Passport numbers require a "passport" keyword because the digit
        // patterns are shared with other ID types.
        //
        // Street addresses require an "address" keyword because a bare street
        // pattern would fire on any numbered list.

        {
            DlpCategory::PII,
            L"Social Security Number (SSN)",
            L"Personal identity information (PII)",
            // Formatted SSN: XXX-XX-XXXX
            // Exclusions: 000/666/9XX prefix, 00 middle group, 0000 last group
            std::regex(R"(\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b)"),
            nullptr
        },
        {
            DlpCategory::PII,
            L"Passport Number",
            L"Personal identity information (PII)",
            // Keyword-gated: "passport number/no/#" then 1 letter + 8 digits
            // OR 9 contiguous digits (generic international format).
            // \b before "passport" prevents matching compound words like
            // "epassport" or "passportapp" that are unrelated document types.
            std::regex(
                R"((?:\bpassport)\s*(?:number|no|#|num)?\s*[:\-]?\s*\b(?:[A-Z]\d{8}|\d{9})\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::PII,
            L"Physical Street Address",
            L"Personal identity information (PII)",
            // Keyword-gated: "address:" or "home/mailing/billing addr" then
            // a street number + name + type suffix
            std::regex(
                R"((?:(?:home|mailing|billing|street|residential)\s*)?address\s*[:\-]?\s*\d{1,5}\s+(?:[A-Za-z0-9]+\s+){1,5}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Court|Ct|Way|Place|Pl|Parkway|Pkwy|Highway|Hwy|Circle|Cir)\.?\b)",
                std::regex_constants::icase),
            nullptr
        },

        // ── PHI: Health & Medical Privacy ─────────────────────────────────────
        // Covers HIPAA's "Safe Harbor" de-identification identifiers that are
        // detectable via pattern matching:
        //   • Medicare Beneficiary Identifier (MBI) — fixed 11-char format
        //   • Patient/MRN identifiers — keyword-gated alphanumeric codes
        //   • ICD-10 diagnosis codes    — keyword-gated clinical codes
        //   • Health insurance member/policy numbers — keyword-gated

        {
            DlpCategory::PHI,
            L"Medicare Beneficiary Identifier (MBI)",
            L"Protected health information (PHI)",
            // MBI is an 11-character alphanumeric code with a precisely defined
            // character-set at each position — low false-positive rate.
            //
            // CMS excluded letters (visually similar to digits): B, I, L, O, S, Z
            // Correct alpha set: A,C-H,J-K,M-N,P-R,T-Y  →  [AC-HJ-KM-NP-RT-Y]
            //
            // Per-position format (CMS "Transition to New Medicare Numbers" spec):
            //   Pos  1: [1-9]                      — non-zero digit
            //   Pos  2: alpha                       — [AC-HJ-KM-NP-RT-Y]
            //   Pos  3: alpha-numeric               — [AC-HJ-KM-NP-RT-Y0-9]
            //   Pos  4: numeric                     — [0-9]
            //   Pos  5: alpha                       — [AC-HJ-KM-NP-RT-Y]
            //   Pos  6: numeric                     — [0-9]
            //   Pos  7: alpha-numeric               — [AC-HJ-KM-NP-RT-Y0-9]
            //   Pos  8: alpha                       — [AC-HJ-KM-NP-RT-Y]
            //   Pos  9: numeric                     — [0-9]
            //   Pos 10: alpha-numeric               — [AC-HJ-KM-NP-RT-Y0-9]
            //   Pos 11: numeric                     — [0-9]
            //
            // Previous (wrong) pattern had 10 chars, used [AC-HJ-NP-RT-Y] which
            // incorrectly included L (J-N) and S (R-T), and excluded Q,U,V,W,X.
            std::regex(
                R"(\b[1-9][AC-HJ-KM-NP-RT-Y][AC-HJ-KM-NP-RT-Y0-9][0-9][AC-HJ-KM-NP-RT-Y][0-9][AC-HJ-KM-NP-RT-Y0-9][AC-HJ-KM-NP-RT-Y][0-9][AC-HJ-KM-NP-RT-Y0-9][0-9]\b)"),
            nullptr
        },
        {
            DlpCategory::PHI,
            L"Patient Identifier / Medical Record Number (MRN)",
            L"Protected health information (PHI)",
            // Requires a "patient id / mrn / medical record number" keyword
            std::regex(
                R"((?:patient\s*(?:id|#|number|no|identifier)|(?:\bmrn\b)|medical\s*record\s*(?:number|no|#))\s*[:\-]?\s*[A-Z0-9]{4,15}\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::PHI,
            L"ICD-10 Diagnosis Code",
            L"Protected health information (PHI)",
            // ICD-10-CM codes must be preceded by diagnosis/icd/dx keyword to
            // avoid matching unrelated alphanumeric codes of similar length
            std::regex(
                R"((?:diagnosis|icd[-\s]?(?:10)?|(?:\bdx\b))\s*[:\-]?\s*[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::PHI,
            L"Health Insurance Member / Policy Number",
            L"Protected health information (PHI)",
            // Keyword-gated: member id, policy number, insurance id/number
            std::regex(
                R"((?:member\s*(?:id|#|number|no)|policy\s*(?:number|no|#)|insurance\s*(?:id|#|number|no))\s*[:\-]?\s*[A-Z0-9]{5,20}\b)",
                std::regex_constants::icase),
            nullptr
        },

        // ── Financial: Banking & Tax Data ──────────────────────────────────────
        // US ABA routing numbers must be preceded by a "routing" or "aba" keyword
        // because 9-digit sequences are common in many other contexts.
        //
        // Bank account numbers are keyword-gated for the same reason.
        //
        // EIN (XX-XXXXXXX) is keyword-gated to avoid matching other XX-XXXXXXX
        // formatted codes (e.g. internal reference numbers).
        //
        // ITIN (9XX-XX-XXXX with specific middle-group digits) is distinctive
        // enough to match without keyword context given the constrained ranges.

        {
            DlpCategory::Financial,
            L"ABA Bank Routing Number",
            L"Banking or tax information (Financial)",
            // Keyword-gated 9-digit ABA number; first 2 digits must be a valid
            // Federal Reserve routing prefix (01-12 or 21-32)
            std::regex(
                R"((?:routing\s*(?:number|no|#|num|transit)|(?:\baba\b))\s*[:\-]?\s*\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::Financial,
            L"Bank Account Number",
            L"Banking or tax information (Financial)",
            // Keyword-gated 4-17 digit account number
            std::regex(
                R"((?:(?:bank\s*)?account\s*(?:number|num|no|#)|(?:\bacct\b)\.?\s*(?:no|#|num)?)\s*[:\-]?\s*\d{4,17}\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::Financial,
            L"Employer Identification Number (EIN)",
            L"Banking or tax information (Financial)",
            // EIN format: XX-XXXXXXX (two-digit prefix, dash, seven digits).
            // Keyword-gated to prevent matching other XX-XXXXXXX codes.
            std::regex(
                R"((?:(?:\bein\b)|employer\s*(?:id|identification)\s*(?:number|no)?|federal\s*tax\s*id(?:entifier)?|tax\s*id(?:entification\s*number)?)\s*[:\-]?\s*\b\d{2}-\d{7}\b)",
                std::regex_constants::icase),
            nullptr
        },
        {
            DlpCategory::Financial,
            L"Individual Taxpayer Identification Number (ITIN)",
            L"Banking or tax information (Financial)",
            // ITINs: 9XX-YY-ZZZZ where YY is in {50-65, 70-88, 90-92, 94-99}
            // The combination of 9XX prefix + restricted middle group is
            // sufficiently constrained to match without a keyword.
            //
            // Middle-group breakdown:
            //   5[0-9]    → 50-59   (part of 50-65 range)
            //   6[0-5]    → 60-65   (completes 50-65 range)
            //   7[0-9]    → 70-79   (part of 70-88 range)
            //   8[0-8]    → 80-88   (completes 70-88 range)
            //   9[0-24-9] → 90-92, 94-99  (covers 90-92 and 94-99; note:
            //               inside a character class [0-24-9] means chars
            //               0,1,2 (via 0-2) and 4-9 (via 4-9), so 93 is
            //               correctly excluded per IRS assignment policy)
            std::regex(
                R"(\b9\d{2}-(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[0-24-9])-\d{4}\b)"),
            nullptr
        },
    };
    return kPatterns;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — ScanText()
// ════════════════════════════════════════════════════════════════════════════

std::vector<DlpMatch> ScanText(const std::string& text, DlpCategory enabledCategories) {
    std::vector<DlpMatch> results;
    uint32_t seenCategories = 0; // bitmask — collapses duplicates within a category

    for (const auto& entry : GetPatterns()) {
        const uint32_t catBit = static_cast<uint32_t>(entry.category);

        // Skip if this category is not in the enabled set
        if (!DlpCategoryEnabled(enabledCategories, entry.category)) continue;

        // Skip if we already have a match for this category (first-match wins)
        if (seenCategories & catBit) continue;

        // Guard against regex_error thrown by sregex_iterator on pathological
        // inputs (excessive backtracking, malformed UTF-8 sequences, etc.).
        // An unhandled exception here propagates through the MinHook trampoline
        // and crashes the host process — so we catch and log, never rethrow.
        try {
            std::sregex_iterator it(text.begin(), text.end(), entry.re);
            const std::sregex_iterator end_it;

            while (it != end_it) {
                // Run optional validator (e.g. Luhn check for credit cards)
                if (!entry.validate || entry.validate(it->str())) {
                    results.push_back({ entry.category, entry.patternName, entry.categoryLabel });
                    seenCategories |= catBit;
                    break; // one match per category is sufficient
                }
                ++it;
            }
        } catch (const std::exception& ex) {
            OutputDebugStringA("[DLP] ScanText: regex exception suppressed — ");
            OutputDebugStringA(ex.what());
        } catch (...) {
            OutputDebugStringA("[DLP] ScanText: unknown exception suppressed in regex scan");
        }
    }
    return results;
}

std::vector<DlpMatch> ScanText(const std::wstring& text, DlpCategory enabledCategories) {
    // Sensitive data patterns are all ASCII-range; a lossy narrow conversion is safe.
    std::string narrow;
    narrow.reserve(text.size());
    for (wchar_t wc : text)
        narrow += (wc < 128) ? static_cast<char>(wc) : '?';
    return ScanText(narrow, enabledCategories);
}

// ── Legacy shims ──────────────────────────────────────────────────────────────

bool ContainsCreditCardData(const std::string& text) {
    return !ScanText(text, DlpCategory::PCI).empty();
}

bool ContainsCreditCardData(const std::wstring& text) {
    return !ScanText(text, DlpCategory::PCI).empty();
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — NotifyUser()
// ════════════════════════════════════════════════════════════════════════════

// Layer 1: atomic flag — true while a dialog is currently visible.
// Prevents duplicate dialogs when multiple clipboard hook detours fire
// concurrently (e.g. CF_TEXT + CF_OEMTEXT + CF_UNICODETEXT in one copy action).
static std::atomic<bool>      g_alertVisible{  false };

// Layer 2: timestamp cooldown — records GetTickCount64() of the last dismissal.
// Absorbs lagging events that arrive while the modal was up.
static std::atomic<ULONGLONG> g_lastAlertTickMs{ 0ULL };

static DWORD WINAPI NotificationThreadProc(LPVOID lpParam) {
    // Take ownership of the heap-allocated message immediately.
    std::unique_ptr<std::wstring> pMsg(static_cast<std::wstring*>(lpParam));

    // ── Guard 1: is another dialog already on screen? ─────────────────────────
    bool expected = false;
    if (!g_alertVisible.compare_exchange_strong(expected, true,
                                                std::memory_order_acquire,
                                                std::memory_order_relaxed))
    {
        OutputDebugStringA("[DLP] NotifyUser: suppressed duplicate alert (dialog already visible)");
        return 0;
    }

    // ── Guard 2: are we within the post-dismiss cooldown window? ─────────────
    const ULONGLONG now      = GetTickCount64();
    const ULONGLONG lastTick = g_lastAlertTickMs.load(std::memory_order_relaxed);
    if (now - lastTick < NOTIFY_COOLDOWN_MS) {
        g_alertVisible.store(false, std::memory_order_release);
        OutputDebugStringA("[DLP] NotifyUser: suppressed duplicate alert (cooldown active)");
        return 0;
    }

    // ── Show the modal (blocks this thread until the user clicks OK) ──────────
    //
    // MB_SYSTEMMODAL is intentionally NOT used here.  When the DLL is injected
    // into a hardware-accelerated host (Chrome/Edge), MB_SYSTEMMODAL causes the
    // dialog to render behind the browser's compositor surface, making the button
    // area invisible to the user.  MB_TOPMOST | MB_SETFOREGROUND correctly floats
    // the dialog above all windows without triggering compositor z-order issues.
    MessageBoxW(nullptr, pMsg->c_str(), L"Browser Bridge Security Alert",
                MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);

    // ── Release guards after dismissal ───────────────────────────────────────
    g_lastAlertTickMs.store(GetTickCount64(), std::memory_order_relaxed);
    g_alertVisible.store(false, std::memory_order_release);
    return 0;
}

void DlpCommon_Shutdown() {
    // No shared memory resources to release.
    OutputDebugStringA("[DLP] DlpCommon: shutdown complete");
}

void NotifyUser(std::wstring message) {
    // Fast pre-checks on the calling thread — avoids spawning a thread
    // when the answer is clearly "suppress".
    if (g_alertVisible.load(std::memory_order_relaxed)) {
        OutputDebugStringA("[DLP] NotifyUser: fast-path suppressed (dialog already visible)");
        return;
    }
    const ULONGLONG now      = GetTickCount64();
    const ULONGLONG lastTick = g_lastAlertTickMs.load(std::memory_order_relaxed);
    if (now - lastTick < NOTIFY_COOLDOWN_MS) {
        OutputDebugStringA("[DLP] NotifyUser: fast-path suppressed (cooldown active)");
        return;
    }

    // Heap-allocate the message so it outlives this stack frame; the thread
    // proc takes ownership via unique_ptr and deletes it after MessageBoxW.
    auto* pMsg = new std::wstring(std::move(message));
    HANDLE hThread = CreateThread(nullptr, 0, NotificationThreadProc, pMsg, 0, nullptr);
    if (hThread) {
        CloseHandle(hThread);
    } else {
        delete pMsg; // Thread creation failed — prevent leak
    }
}
