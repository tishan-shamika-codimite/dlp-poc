#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

// ── DLP Category bitmask ──────────────────────────────────────────────────────
//
//  Each bit represents one data-sensitivity domain.  Multiple bits may be OR'd
//  together when calling ScanText() to restrict which categories are checked.
//
enum class DlpCategory : uint32_t {
    None        = 0,
    PCI         = 1 << 0,   // Payment & Cardholder Data  (credit cards, CVV, expiry)
    PII         = 1 << 1,   // Individual Identity         (SSN, passport, address)
    PHI         = 1 << 2,   // Health & Medical Privacy    (patient IDs, diagnoses, insurance)
    Financial   = 1 << 3,   // Banking & Tax Data          (routing, account, EIN, ITIN)
    All         = 0xFFFFFFFFu
};

inline DlpCategory operator|(DlpCategory a, DlpCategory b) {
    return static_cast<DlpCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool DlpCategoryEnabled(DlpCategory flags, DlpCategory test) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(test)) != 0;
}

// ── Match result ──────────────────────────────────────────────────────────────
//
//  Returned by ScanText() for each category that triggered.  At most one
//  DlpMatch per category is returned (highest-confidence pattern wins).
//
struct DlpMatch {
    DlpCategory     category;       // Which category triggered
    const wchar_t*  patternName;    // e.g. L"Credit Card Number"
    const wchar_t*  categoryLabel;  // e.g. L"Payment card data (PCI)"
};

// ── Multi-category scanner ────────────────────────────────────────────────────
//
//  Scans the supplied text against every registered sensitive-data pattern.
//  Returns one DlpMatch per triggered category (duplicates within the same
//  category are collapsed — the first matching pattern wins).
//
[[nodiscard]] std::vector<DlpMatch> ScanText(
    const std::string&  text,
    DlpCategory         enabledCategories = DlpCategory::All);

[[nodiscard]] std::vector<DlpMatch> ScanText(
    const std::wstring& text,
    DlpCategory         enabledCategories = DlpCategory::All);

// ── Legacy shims (backward compatibility) ────────────────────────────────────
[[nodiscard]] bool ContainsCreditCardData(const std::string&  text);
[[nodiscard]] bool ContainsCreditCardData(const std::wstring& text);

// ── User notification ─────────────────────────────────────────────────────────
//
//  Shows a non-blocking "Browser Bridge Security Alert" dialog in the target
//  process.  Ownership of `message` is transferred to the function.
//
//  Duplicate calls while a dialog is already on screen, or within
//  NOTIFY_COOLDOWN_MS of the last dismissal, are silently suppressed — this
//  prevents alert storms from applications (e.g. Adobe Acrobat) that fire
//  multiple clipboard API calls for a single logical copy action.
//
void NotifyUser(std::wstring message);

// Cooldown window (ms) after dismissal during which new alerts are suppressed.
static constexpr ULONGLONG NOTIFY_COOLDOWN_MS = 1000ULL;

// Releases the cross-process shared memory handles.  Call from DLL_PROCESS_DETACH
// AFTER all hooks have been removed.
void DlpCommon_Shutdown();
