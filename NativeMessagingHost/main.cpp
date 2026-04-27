#include "JsonMessage.h"
#include "ScreenShareDetector.h"
#include "RegistrySetup.h"
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <string>
#include <thread>
#include <atomic>
#include <cstdio>

// ── Globals ───────────────────────────────────────────────────────────────────

static std::atomic<bool> g_running{ true };

// ── JSON helpers ──────────────────────────────────────────────────────────────

static std::string MakeScreenShareMsg(bool active) {
    return std::string("{\"type\":\"screenshare\",\"active\":") +
           (active ? "true" : "false") + "}";
}

static std::string MakePingResponse() {
    return "{\"type\":\"pong\"}";
}

// ── Stdin reader thread ───────────────────────────────────────────────────────
// Reads messages from the extension (e.g. ping, config updates).
// Exits when the browser closes the pipe (ReadFile returns false → EOF).

static void StdinReaderThread() {
    std::string json;
    while (g_running.load()) {
        if (!NM_ReadMessage(json)) {
            // Browser disconnected — signal main loop to exit
            g_running.store(false);
            break;
        }
        // Handle ping from extension
        if (json.find("\"ping\"") != std::string::npos) {
            NM_WriteMessage(MakePingResponse());
        }
        // Future: handle domain config updates from extension here
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[]) {
    // Switch stdin/stdout to binary mode — required for Native Messaging protocol.
    // Text mode on Windows translates \n → \r\n which corrupts the 4-byte length.
    _setmode(_fileno(stdin),  _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);

    // ── CLI argument handling ─────────────────────────────────────────────────
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    for (int i = 1; i < argc; i++) {
        std::wstring arg(argv[i]);
        if (arg == L"--register") {
            // Optional: NativeMessagingHost.exe --register <extension-id>
            const wchar_t* extId = (i + 1 < argc) ? argv[i + 1] : nullptr;
            bool ok = RegistrySetup_Register(exePath, extId);
            if (ok) {
                if (extId)
                    wprintf(L"Registered with extension ID: %s\n", extId);
                else
                    wprintf(L"Registered (extension ID preserved or placeholder kept).\n");
            } else {
                wprintf(L"Registration failed.\n");
            }
            return ok ? 0 : 1;
        }
        if (arg == L"--unregister") {
            bool ok = RegistrySetup_Unregister();
            return ok ? 0 : 1;
        }
    }

    // ── Auto-register if needed ───────────────────────────────────────────────
    RegistrySetup_EnsureRegistered(exePath);

    // ── Start screen share detection ──────────────────────────────────────────
    ScreenShareDetector_Start();

    // ── Start stdin reader thread ─────────────────────────────────────────────
    std::thread reader(StdinReaderThread);

    // ── Main message loop ─────────────────────────────────────────────────────
    // Poll detection state and send updates to extension on state change.
    bool lastState = false;

    while (g_running.load()) {
        bool current = ScreenShareDetector_IsSharing();

        if (current != lastState) {
            lastState = current;
            NM_WriteMessage(MakeScreenShareMsg(current));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    ScreenShareDetector_Stop();

    if (reader.joinable())
        reader.join();

    return 0;
}
