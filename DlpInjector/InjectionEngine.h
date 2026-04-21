#pragma once
#include <windows.h>

// Starts the DLP injection monitoring loop.
// Blocks until hStopEvent is signalled, then returns.
// Uses ETW (Event Tracing for Windows) for zero-delay process-birth detection
// AND a polling fallback for processes that start before ETW subscription is ready.
void StartMonitoring(HANDLE hStopEvent);

// Attempts to enable SeDebugPrivilege on the current process token.
// Required to open handles to processes owned by other users (SYSTEM, etc.).
// Returns TRUE if the privilege was successfully enabled.
bool EnableDebugPrivilege();

