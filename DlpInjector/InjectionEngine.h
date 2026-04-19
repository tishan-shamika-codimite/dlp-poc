#pragma once
#include <windows.h>

// Starts the DLL injection monitoring loop.
// Blocks until hStopEvent is signaled, then returns.
void StartMonitoring(HANDLE hStopEvent);
