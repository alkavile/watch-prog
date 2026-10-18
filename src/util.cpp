#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "util.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cwctype>
#include <memory>
#include <sstream>
#include <tlhelp32.h>
#include <shlobj.h>

namespace {

std::wstring FormatMessageText(DWORD code) {
    LPWSTR buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring result;
    if (len && buffer) result.assign(buffer, len);
    if (buffer) LocalFree(buffer);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ' || result.back() == L'.'))
        result.pop_back();
    return result;
}

std::wstring QueryDosName(const std::wstring& drive) {
    wchar_t target[1024] = {};
    if (QueryDosDeviceW(drive.c_str(), target, 1024) == 0) return L"";
    return target;
}

const std::vector<std::pair<std::wstring, std::wstring>>& VolumeMap() {
    static std::vector<std::pair<std::wstring, std::wstring>> map;
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        wchar_t windows[MAX_PATH] = {};
        GetWindowsDirectoryW(windows, MAX_PATH);
        std::wstring win = windows;
        map.push_back({ L"\\SystemRoot", win });
        map.push_back({ L"\\Windows", win });
        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            std::wstring drive(1, letter);
            drive += L":";
            std::wstring target = QueryDosName(drive);
            if (!target.empty()) map.push_back({ target, drive });
        }
        std::sort(map.begin(), map.end(), [](const auto& a, const auto& b) {
            return a.first.size() > b.first.size();
        });
    }
    return map;
}

bool StartsWithNoCase(const std::wstring& value, const std::wstring& prefix) {
    if (value.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (towlower(value[i]) != towlower(prefix[i])) return false;
    }
    return true;
}

std::wstring ProcessNameFallback(DWORD pid) {
    wchar_t name[MAX_PATH] = {};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    wcsncpy(name, pe.szExeFile, MAX_PATH - 1);
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return name;
}

} // namespace

std::wstring GetExePath() {
    std::vector<wchar_t> buffer(1024);
    for (;;) {
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) return L"";
        if (len < buffer.size() - 1) return std::wstring(buffer.data(), len);
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) break;
    }
    return L"";
}

std::wstring GetExeDirectory() {
    return DirectoryOf(GetExePath());
}

std::wstring JoinPath(const std::wstring& dir, const std::wstring& name) {
    if (dir.empty()) return name;
    if (name.empty()) return dir;
    wchar_t last = dir.back();
    if (last == L'\\' || last == L'/') return dir + name;
    return dir + L"\\" + name;
}

std::wstring FileNameOf(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

std::wstring DirectoryOf(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L"";
    if (pos == 0) return path.substr(0, 1);
    return path.substr(0, pos);
}

std::wstring ExtensionOf(const std::wstring& path) {
    std::wstring name = FileNameOf(path);
    size_t pos = name.find_last_of(L'.');
    if (pos == std::wstring::npos) return L"";
    return ToLower(name.substr(pos));
}

std::wstring StripExtension(const std::wstring& name) {
    size_t pos = name.find_last_of(L'.');
    if (pos == std::wstring::npos) return name;
    return name.substr(0, pos);
}

bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectory(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

unsigned long long FileSizeOf(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return 0;
    ULARGE_INTEGER size = {};
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    return size.QuadPart;
}

std::wstring FormatBytes(unsigned long long bytes) {
    const wchar_t* units[] = { L"Б", L"КБ", L"МБ", L"ГБ", L"ТБ" };
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::wostringstream out;
    if (unit == 0) {
        out << bytes << L" " << units[unit];
    } else if (value < 10.0) {
        out.setf(std::ios::fixed);
        out.precision(2);
        out << value << L" " << units[unit];
    } else if (value < 100.0) {
        out.setf(std::ios::fixed);
        out.precision(1);
        out << value << L" " << units[unit];
    } else {
        out.setf(std::ios::fixed);
        out.precision(0);
        out << value << L" " << units[unit];
    }
    std::wstring text = out.str();
    size_t dot = text.find(L'.');
    if (dot != std::wstring::npos) {
        size_t i = dot;
        for (wchar_t& c : text) {
            if (c == L'.') c = L',';
            (void)i;
        }
    }
    return text;
}

std::wstring FormatDateTime(const FILETIME& ft, bool secondsOnly) {
    FILETIME local = {};
    FileTimeToLocalFileTime(&ft, &local);
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&local, &st);
    wchar_t buffer[64] = {};
    if (secondsOnly) {
        swprintf(buffer, 64, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    } else {
        swprintf(buffer, 64, L"%02u.%02u.%04u %02u:%02u:%02u", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    }
    return buffer;
}

FILETIME NowFileTime() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    return ft;
}

ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER value = {};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

FILETIME U64ToFileTime(ULONGLONG value) {
    ULARGE_INTEGER u = {};
    u.QuadPart = value;
    FILETIME ft = {};
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    return ft;
}

std::wstring FormatWinError(DWORD code) {
    std::wstring message = FormatMessageText(code);
    if (message.empty()) message = L"Неизвестная ошибка";
    wchar_t buffer[64] = {};
    swprintf(buffer, 64, L" (код %lu)", code);
    return message + buffer;
}

std::wstring FormatInt(unsigned long long value) {
    return std::to_wstring(value);
}

std::wstring FormatPid(DWORD pid) {
    wchar_t buffer[32] = {};
    swprintf(buffer, 32, L"%lu", pid);
    return buffer;
}

std::wstring GetProcessPath(DWORD pid) {
    if (pid == 0) return L"";
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return L"";
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    std::wstring result;
    if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        result.assign(buffer.data(), size);
    }
    CloseHandle(process);
    return result;
}

std::wstring GetProcessName(DWORD pid) {
    std::wstring path = GetProcessPath(pid);
    if (!path.empty()) return FileNameOf(path);
    std::wstring fallback = ProcessNameFallback(pid);
    if (!fallback.empty()) return fallback;
    return L"процесс";
}

bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool IsSupportedExtension(const std::wstring& ext) {
    static const wchar_t* list[] = {
        L".exe", L".msi", L".appx", L".appinstaller", L".msix", L".msixbundle",
        L".appxbundle", L".com", L".bat", L".vbs", L".ps1", L".dll", L".vbe",
        L".cmd", L".cpl", L".msc", L".scr"
    };
    for (const wchar_t* item : list) {
        if (ext == item) return true;
    }
    // The task text uses a Cyrillic "c" in msc in some places. Accept it too.
    return ext == L".ms\u0441";
}

std::wstring SupportedExtensionsText() {
    return L"EXE, MSI, APPX, APPINSTALLER, MSIX, MSIXBUNDLE, APPXBUNDLE, COM, BAT, VBS, PS1, DLL, VBE, CMD, CPL, MSC, SCR";
}

std::wstring EscapeField(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
            case L'\\': out += L"\\\\"; break;
            case L'\t': out += L"\\t"; break;
            case L'\n': out += L"\\n"; break;
            case L'\r': out += L"\\r"; break;
            default: out += c; break;
        }
    }
    return out;
}

std::wstring UnescapeField(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t c = s[i];
        if (c == L'\\' && i + 1 < s.size()) {
            wchar_t n = s[++i];
            switch (n) {
                case L'\\': out += L'\\'; break;
                case L't': out += L'\t'; break;
                case L'n': out += L'\n'; break;
                case L'r': out += L'\r'; break;
                default: out += L'\\'; out += n; break;
            }
        } else {
            out += c;
        }
    }
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size);
    return out;
}

std::wstring NormalizeNtPath(const std::wstring& input) {
    if (input.empty()) return input;
    std::wstring path = input;
    if (StartsWithNoCase(path, L"\\\\?\\")) path = path.substr(4);
    if (StartsWithNoCase(path, L"\\??\\")) path = path.substr(4);
    auto trimTrailing = [](std::wstring& value) {
        while (value.size() > 3 && value.back() == L'\\' && value[value.size() - 2] != L':') {
            value.pop_back();
        }
    };
    if (path.size() >= 2 && std::iswalpha(path[0]) && path[1] == L':') {
        trimTrailing(path);
        return path;
    }
    for (const auto& mapping : VolumeMap()) {
        if (mapping.first.empty()) continue;
        if (StartsWithNoCase(path, mapping.first)) {
            std::wstring rest = path.substr(mapping.first.size());
            if (!rest.empty() && rest[0] != L'\\') rest = L"\\" + rest;
            std::wstring result = mapping.second + rest;
            trimTrailing(result);
            return result;
        }
    }
    trimTrailing(path);
    return path;
}

std::wstring NormalizeRegistryPath(const std::wstring& input) {
    std::wstring path = input;
    while (!path.empty() && path[0] == L'\\') path.erase(path.begin());
    if (StartsWithNoCase(path, L"REGISTRY\\")) path = path.substr(9);
    if (StartsWithNoCase(path, L"MACHINE\\")) return L"HKLM\\" + path.substr(8);
    if (StartsWithNoCase(path, L"MACHINE")) return L"HKLM";
    if (StartsWithNoCase(path, L"USER\\")) return L"HKU\\" + path.substr(5);
    if (StartsWithNoCase(path, L"USER")) return L"HKU";
    if (StartsWithNoCase(path, L"HKLM") || StartsWithNoCase(path, L"HKU") || StartsWithNoCase(path, L"HKCU"))
        return path;
    if (StartsWithNoCase(path, L"\\REGISTRY")) return path;
    if (path.empty()) return L"";
    // Some kernel-registry CreateKey events give only a relative name for
    // handles based on a predefined root. The common per-user roots are the
    // only ones where the base name is not part of the event.
    if (StartsWithNoCase(path, L"Software") || StartsWithNoCase(path, L"Environment") ||
        StartsWithNoCase(path, L"Control Panel") || StartsWithNoCase(path, L"Console")) {
        return L"HKCU\\" + path;
    }
    return path;
}

std::wstring ComposeRegistryKey(const std::wstring& base, const std::wstring& relative) {
    std::wstring b = base;
    std::wstring r = relative;
    while (!b.empty() && b.back() == L'\\') b.pop_back();
    while (!r.empty() && r[0] == L'\\') r.erase(r.begin());
    if (r.empty()) return NormalizeRegistryPath(b);
    if (StartsWithNoCase(r, L"REGISTRY\\")) return NormalizeRegistryPath(r);
    if (StartsWithNoCase(r, L"HKLM") || StartsWithNoCase(r, L"HKU") || StartsWithNoCase(r, L"HKCU"))
        return NormalizeRegistryPath(r);
    if (b.empty()) return NormalizeRegistryPath(r);
    if (StartsWithNoCase(r, b)) return NormalizeRegistryPath(r);
    return NormalizeRegistryPath(b + L"\\" + r);
}

std::wstring FormatIpv4(unsigned long value) {
    wchar_t buffer[32] = {};
    swprintf(buffer, 32, L"%u.%u.%u.%u",
             static_cast<unsigned>(value & 0xFF),
             static_cast<unsigned>((value >> 8) & 0xFF),
             static_cast<unsigned>((value >> 16) & 0xFF),
             static_cast<unsigned>((value >> 24) & 0xFF));
    return buffer;
}

std::wstring FormatIpv6(const BYTE bytes[16]) {
    unsigned groups[8] = {};
    for (int i = 0; i < 8; ++i) groups[i] = (static_cast<unsigned>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
    int bestStart = -1, bestLen = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) { ++i; continue; }
        int j = i;
        while (j < 8 && groups[j] == 0) ++j;
        if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
        i = j;
    }
    if (bestLen < 2) bestStart = -1;
    std::wstring out;
    wchar_t buf[16] = {};
    for (int i = 0; i < 8; ++i) {
        if (i == bestStart) {
            out += L"::";
            i += bestLen - 1;
            continue;
        }
        if (!out.empty() && out.back() != L':') out += L':';
        swprintf(buf, 16, L"%x", groups[i]);
        out += buf;
    }
    if (out.empty()) out = L"::";
    return out;
}

std::wstring FormatEndpoint(const std::wstring& host, unsigned port) {
    if (host.find(L':') != std::wstring::npos) {
        return L"[" + host + L"]:" + std::to_wstring(port);
    }
    return host + L":" + std::to_wstring(port);
}

std::vector<std::wstring> LocalIpAddresses() {
    std::vector<std::wstring> result;
    result.push_back(L"127.0.0.1");
    result.push_back(L"::1");
    ULONG size = 16 * 1024;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<BYTE> buffer(size);
        auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ULONG status = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, addresses, &size);
        if (status == ERROR_BUFFER_OVERFLOW) continue;
        if (status != ERROR_SUCCESS) return result;
        for (auto* adapter = addresses; adapter; adapter = adapter->Next) {
            for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (!unicast->Address.lpSockaddr) continue;
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                    result.push_back(FormatIpv4(sa->sin_addr.S_un.S_addr));
                } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* sa = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                    std::wstring address = FormatIpv6(sa->sin6_addr.u.Byte);
                    size_t scope = address.find(L'%');
                    if (scope != std::wstring::npos) address.resize(scope);
                    result.push_back(address);
                }
            }
        }
        break;
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

std::wstring BuildUrl(const std::wstring& host, unsigned port, bool udp) {
    if (udp) {
        if (port == 53) return L"dns://" + host;
        return L"udp://" + FormatEndpoint(host, port);
    }
    if (port == 80) return L"http://" + host + L"/";
    if (port == 443) return L"https://" + host + L"/";
    if (port == 8080) return L"http://" + FormatEndpoint(host, port) + L"/";
    if (port == 53) return L"dns://" + host;
    return L"tcp://" + FormatEndpoint(host, port);
}

std::wstring QuoteArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    bool need = arg.find_first_of(L" \t\n\v\"") != std::wstring::npos;
    if (!need) return arg;
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out += L'"';
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            out += c;
            backslashes = 0;
        }
    }
    out.append(backslashes * 2, L'\\');
    out += L'"';
    return out;
}

std::wstring ToLower(std::wstring s) {
    for (wchar_t& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

std::wstring Trim(std::wstring s) {
    size_t begin = 0;
    while (begin < s.size() && iswspace(s[begin])) ++begin;
    size_t end = s.size();
    while (end > begin && iswspace(s[end - 1])) --end;
    return s.substr(begin, end - begin);
}

bool StartsWithI(const std::wstring& s, const std::wstring& prefix) {
    return StartsWithNoCase(s, prefix);
}

bool EndsWithI(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    return StartsWithNoCase(s.substr(s.size() - suffix.size()), suffix);
}

const wchar_t* CategoryName(int category) {
    switch (category) {
        case CatFile: return L"Файлы";
        case CatRegistry: return L"Реестр";
        case CatTasks: return L"Задачи";
        case CatProcess: return L"Процессы";
        case CatNetwork: return L"Сеть";
        case CatSystem: return L"Система";
        default: return L"Событие";
    }
}
