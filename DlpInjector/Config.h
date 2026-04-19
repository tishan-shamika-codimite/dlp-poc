#pragma once

// Service identity constants — single source of truth for the service name,
// display name, and description used across ServiceMain, installer, and CLI.
constexpr wchar_t kServiceName[]        = L"DlpService";
constexpr wchar_t kServiceDisplayName[] = L"DLP Agent Service";
constexpr wchar_t kServiceDescription[] = L"Monitors clipboard and file operations to block credit card data leakage";
