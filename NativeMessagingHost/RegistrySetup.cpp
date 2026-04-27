#include "RegistrySetup.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <fstream>

// ── Constants ─────────────────────────────────────────────────────────────────

static constexpr wchar_t kHostName[]    = L"com.dlp.screenshare";
static constexpr wchar_t kManifestName[] = L"com.dlp.screenshare.json";

// Chrome and Edge native messaging registry paths (HKCU — no elevation needed)
static const wchar_t* kRegPaths[] = {
    L"Software\\Google\\Chrome\\NativeMessagingHosts\\com.dlp.screenshare",
    L"Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.dlp.screenshare",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// Returns %LOCALAPPDATA%\DlpAgent\  (created if absent)
static std::wstring GetManifestDir() {
    wchar_t localApp[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localApp);
    std::wstring dir = std::wstring(localApp) + L"\\DlpAgent";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

// Converts a wide string to UTF-8 std::string.
static std::string WideToUtf8(const wchar_t* wide) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &s[0], len, nullptr, nullptr);
    return s;
}

// Reads the extension ID from an existing manifest (if any), so --register
// without an ID preserves the previously set extension ID.
static std::string ReadExistingExtensionId(const std::wstring& manifestPath) {
    std::ifstream f(manifestPath, std::ios::in | std::ios::binary);
    if (!f) return {};
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    // Look for "chrome-extension://<id>/"
    const std::string prefix = "chrome-extension://";
    auto pos = content.find(prefix);
    if (pos == std::string::npos) return {};
    pos += prefix.size();
    auto end = content.find('/', pos);
    if (end == std::string::npos) return {};
    std::string id = content.substr(pos, end - pos);
    if (id == "REPLACE_WITH_YOUR_EXTENSION_ID") return {};
    return id;
}

// Writes the NM host JSON manifest to disk and returns its path.
static std::wstring WriteManifest(const wchar_t* exePath, const wchar_t* extensionId) {
    std::wstring dir  = GetManifestDir();
    std::wstring path = dir + L"\\" + kManifestName;

    // Convert wide exe path to UTF-8 for JSON
    std::string exeUtf8 = WideToUtf8(exePath);

    // Escape backslashes for JSON
    std::string escaped;
    for (char c : exeUtf8) {
        if (c == '\\') escaped += "\\\\";
        else           escaped += c;
    }

    // Resolve extension ID: prefer CLI arg, then existing manifest, then placeholder
    std::string extId;
    if (extensionId && extensionId[0] != L'\0') {
        extId = WideToUtf8(extensionId);
    } else {
        extId = ReadExistingExtensionId(path);
    }
    if (extId.empty()) {
        extId = "REPLACE_WITH_YOUR_EXTENSION_ID";
    }

    // NOTE: allowed_origins lists the extension IDs that may connect.
    // During development use the unpacked extension ID shown in chrome://extensions.
    // Replace with the published CRX ID before production deployment.
    std::string json =
        "{\n"
        "  \"name\": \"com.dlp.screenshare\",\n"
        "  \"description\": \"DLP Screen Share Detector - Native Messaging Host\",\n"
        "  \"path\": \"" + escaped + "\",\n"
        "  \"type\": \"stdio\",\n"
        "  \"allowed_origins\": [\n"
        "    \"chrome-extension://" + extId + "/\"\n"
        "  ]\n"
        "}\n";

    // Write as UTF-8 (no BOM)
    std::ofstream f(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!f) return {};
    f.write(json.c_str(), json.size());
    f.close();

    return path;
}

// Sets one registry key (Default) = manifestPath under HKCU.
static bool SetRegKey(const wchar_t* subKey, const std::wstring& manifestPath) {
    HKEY hKey = nullptr;
    DWORD disp = 0;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                        &hKey, &disp) != ERROR_SUCCESS)
        return false;

    LONG ret = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(manifestPath.c_str()),
        static_cast<DWORD>((manifestPath.size() + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    return ret == ERROR_SUCCESS;
}

// ── Public API ────────────────────────────────────────────────────────────────

bool RegistrySetup_Register(const wchar_t* exePath, const wchar_t* extensionId) {
    std::wstring manifestPath = WriteManifest(exePath, extensionId);
    if (manifestPath.empty()) return false;

    bool ok = true;
    for (const wchar_t* path : kRegPaths) {
        ok &= SetRegKey(path, manifestPath);
    }
    return ok;
}

bool RegistrySetup_Unregister() {
    bool ok = true;
    for (const wchar_t* path : kRegPaths) {
        LONG ret = RegDeleteKeyW(HKEY_CURRENT_USER, path);
        ok &= (ret == ERROR_SUCCESS || ret == ERROR_FILE_NOT_FOUND);
    }

    // Remove manifest file
    std::wstring dir  = GetManifestDir();
    std::wstring path = dir + L"\\" + kManifestName;
    DeleteFileW(path.c_str());
    return ok;
}

void RegistrySetup_EnsureRegistered(const wchar_t* exePath) {
    // Check if the Chrome key exists and its value points to an existing file
    HKEY hKey = nullptr;
    bool needsReg = true;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegPaths[0], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t val[MAX_PATH] = {};
        DWORD sz = sizeof(val);
        if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr,
                             reinterpret_cast<BYTE*>(val), &sz) == ERROR_SUCCESS) {
            if (GetFileAttributesW(val) != INVALID_FILE_ATTRIBUTES)
                needsReg = false;
        }
        RegCloseKey(hKey);
    }

    if (needsReg) {
        RegistrySetup_Register(exePath);
    }
}
