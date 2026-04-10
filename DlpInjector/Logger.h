#pragma once
#include <windows.h>
#include <string>

void LogInit();
void LogShutdown();
void LogInfo(const std::wstring& message);
void LogError(const std::wstring& message);
