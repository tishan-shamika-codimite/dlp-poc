#pragma once
#include <windows.h>

// Starts the monitoring loop. Blocks until hStopEvent is signaled.
void StartMonitoring(HANDLE hStopEvent);
