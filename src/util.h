#ifndef WATCHPROG_UTIL_H
#define WATCHPROG_UTIL_H

#include "app.h"
#include <functional>

std::wstring GetExePath();
std::wstring GetExeDirectory();
std::wstring JoinPath(const std::wstring& dir, const std::wstring& name);
std::wstring FileNameOf(const std::wstring& path);
std::wstring DirectoryOf(const std::wstring& path);
std::wstring ExtensionOf(const std::wstring& path);
std::wstring StripExtension(const std::wstring& name);
bool FileExists(const std::wstring& path);
bool IsDirectory(const std::wstring& path);
unsigned long long FileSizeOf(const std::wstring& path);
std::wstring FormatBytes(unsigned long long bytes);
std::wstring FormatDateTime(const FILETIME& ft, bool secondsOnly = false);
FILETIME NowFileTime();
ULONGLONG FileTimeToU64(const FILETIME& ft);
FILETIME U64ToFileTime(ULONGLONG value);
std::wstring FormatWinError(DWORD code);
std::wstring FormatInt(unsigned long long value);
std::wstring FormatPid(DWORD pid);
std::wstring GetProcessName(DWORD pid);
std::wstring GetProcessPath(DWORD pid);
bool IsProcessElevated();
bool IsSupportedExtension(const std::wstring& ext);
std::wstring SupportedExtensionsText();
std::wstring EscapeField(const std::wstring& s);
std::wstring UnescapeField(const std::wstring& s);
std::string WideToUtf8(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);
std::wstring NormalizeNtPath(const std::wstring& path);
std::wstring NormalizeRegistryPath(const std::wstring& path);
std::wstring ComposeRegistryKey(const std::wstring& base, const std::wstring& relative);
std::wstring FormatIpv4(unsigned long value);
std::wstring FormatIpv6(const BYTE bytes[16]);
std::wstring FormatEndpoint(const std::wstring& host, unsigned port);
std::wstring BuildUrl(const std::wstring& host, unsigned port, bool udp);
std::vector<std::wstring> LocalIpAddresses();
std::wstring QuoteArg(const std::wstring& arg);
std::wstring ToLower(std::wstring s);
std::wstring Trim(std::wstring s);
bool StartsWithI(const std::wstring& s, const std::wstring& prefix);
bool EndsWithI(const std::wstring& s, const std::wstring& suffix);

#endif

