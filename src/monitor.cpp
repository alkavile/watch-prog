#include "monitor.h"
#include "etw.h"
#include "util.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

const GUID kKernelFile = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };
const GUID kKernelRegistry = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };
const GUID kKernelNetwork = { 0x7DD42A49, 0x5329, 0x4832, { 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 } };
const GUID kTaskScheduler = { 0xDE7B24EA, 0x73C8, 0x4A09, { 0x98, 0x5D, 0x5B, 0xDA, 0xDC, 0xFA, 0x90, 0x17 } };
const GUID kDnsClient = { 0x1C95126E, 0x7EEA, 0x49A9, { 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D } };
const GUID kWinInet = { 0x43D1A55C, 0x76D6, 0x4F7E, { 0x99, 0x5C, 0x64, 0xC7, 0x11, 0xE5, 0xCA, 0xFE } };
const GUID kWinInetCapture = { 0xA70FF94F, 0x570B, 0x4979, { 0xBA, 0x5C, 0xE5, 0x9C, 0xFE, 0xAB, 0x61, 0xB1 } };
const GUID kWinHttp = { 0x7D44233D, 0x3055, 0x4B9C, { 0xBA, 0x64, 0x0D, 0x47, 0xCA, 0x40, 0xA2, 0x32 } };

constexpr ULONGLONG kFileKeywords = 0x1EF0;      // Create/Write/DeletePath/RenamePath, no Read
constexpr ULONGLONG kRegistryKeywords = 0x5644;  // Create/Delete key, set/delete value, set info/security
constexpr ULONGLONG kNetworkKeywords = 0x30;     // IPv4 + IPv6

std::atomic<unsigned> g_sessionCounter{ 0 };

std::wstring MakeSessionName(const wchar_t* prefix) {
    unsigned n = ++g_sessionCounter;
    wchar_t buffer[160] = {};
    swprintf(buffer, 160, L"WatchProg-%ls-%lu-%u", prefix, GetCurrentProcessId(), n);
    return buffer;
}

std::wstring TruncateText(const std::wstring& text, size_t maxChars) {
    if (text.size() <= maxChars) return text;
    return text.substr(0, maxChars) + L"...";
}

std::wstring RegTypeName(DWORD type) {
    switch (type) {
        case REG_SZ: return L"REG_SZ";
        case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
        case REG_BINARY: return L"REG_BINARY";
        case REG_DWORD: return L"REG_DWORD";
        case REG_DWORD_BIG_ENDIAN: return L"REG_DWORD_BIG_ENDIAN";
        case REG_LINK: return L"REG_LINK";
        case REG_MULTI_SZ: return L"REG_MULTI_SZ";
        case REG_RESOURCE_LIST: return L"REG_RESOURCE_LIST";
        case REG_FULL_RESOURCE_DESCRIPTOR: return L"REG_FULL_RESOURCE_DESCRIPTOR";
        case REG_RESOURCE_REQUIREMENTS_LIST: return L"REG_RESOURCE_REQUIREMENTS_LIST";
        case REG_QWORD: return L"REG_QWORD";
        case REG_NONE: return L"REG_NONE";
        default: return L"тип " + std::to_wstring(type);
    }
}

std::wstring RegDataText(DWORD type, const std::vector<BYTE>& data) {
    if (data.empty()) return L"(пусто)";
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_LINK) {
        std::wstring text;
        size_t chars = data.size() / sizeof(wchar_t);
        if (chars) {
            text.assign(reinterpret_cast<const wchar_t*>(data.data()), chars);
            size_t nullPos = text.find(L'\0');
            if (nullPos != std::wstring::npos) text.resize(nullPos);
        }
        return TruncateText(text, 220);
    }
    if (type == REG_MULTI_SZ) {
        std::wstring result;
        size_t chars = data.size() / sizeof(wchar_t);
        const wchar_t* p = reinterpret_cast<const wchar_t*>(data.data());
        size_t start = 0;
        for (size_t i = 0; i < chars; ++i) {
            if (p[i] == L'\0') {
                if (i > start) {
                    if (!result.empty()) result += L" | ";
                    result.append(p + start, i - start);
                }
                start = i + 1;
            }
        }
        return TruncateText(result, 220);
    }
    if (type == REG_DWORD && data.size() >= 4) {
        DWORD value = 0;
        memcpy(&value, data.data(), 4);
        wchar_t buffer[32] = {};
        swprintf(buffer, 32, L"%lu (0x%08lX)", value, value);
        return buffer;
    }
    if (type == REG_QWORD && data.size() >= 8) {
        ULONGLONG value = 0;
        memcpy(&value, data.data(), 8);
        wchar_t buffer[48] = {};
        swprintf(buffer, 48, L"%llu (0x%016llX)", value, value);
        return buffer;
    }
    if (type == REG_DWORD_BIG_ENDIAN && data.size() >= 4) {
        DWORD value = (static_cast<DWORD>(data[0]) << 24) | (static_cast<DWORD>(data[1]) << 16) |
                      (static_cast<DWORD>(data[2]) << 8) | data[3];
        wchar_t buffer[32] = {};
        swprintf(buffer, 32, L"%lu (0x%08lX)", value, value);
        return buffer;
    }
    static const wchar_t* hex = L"0123456789ABCDEF";
    std::wstring result;
    size_t count = std::min<size_t>(data.size(), 48);
    for (size_t i = 0; i < count; ++i) {
        if (i) result += L' ';
        BYTE b = data[i];
        result += hex[b >> 4];
        result += hex[b & 0x0F];
    }
    if (data.size() > count) result += L" ...";
    return TruncateText(result, 260);
}

bool IsDirectoryAttribute(DWORD attributes) {
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool IsInstrumentationNoisePath(const std::wstring& path) {
    // Windhawk injects bookkeeping writes into every process on machines where
    // its mods are active. These writes are not actions of the dropped file.
    return StartsWithI(path, L"C:\\ProgramData\\Windhawk\\Engine\\") ||
           StartsWithI(path, L"C:\\Program Files\\Windhawk\\Engine\\") ||
           StartsWithI(path, L"C:\\Program Files (x86)\\Windhawk\\Engine\\");
}

std::wstring ParentInfo(std::unordered_map<DWORD, PROCESSENTRY32W>& snapshot, DWORD parentPid) {
    auto it = snapshot.find(parentPid);
    if (it != snapshot.end() && it->second.szExeFile[0]) {
        return std::wstring(it->second.szExeFile) + L" (PID " + FormatPid(parentPid) + L")";
    }
    return L"PID " + FormatPid(parentPid);
}

FILETIME EventTime(PEVENT_RECORD record) {
    FILETIME ft = {};
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    return ft;
}

struct FileRef {
    std::wstring path;
    bool isDir = false;
};

struct ProcessNode {
    DWORD pid = 0;
    DWORD parentPid = 0;
    bool active = true;
    bool special = false;
    bool startReported = false;
    HANDLE handle = nullptr;
    std::wstring path;
    std::wstring name;
    FILETIME created{};
};

struct WriteKey {
    std::wstring path;
    DWORD pid = 0;
    bool operator==(const WriteKey& other) const { return pid == other.pid && path == other.path; }
};

struct WriteKeyHash {
    size_t operator()(const WriteKey& key) const {
        size_t h = std::hash<std::wstring>()(key.path);
        h ^= static_cast<size_t>(key.pid) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct WriteAggregate {
    FILETIME first{};
    FILETIME last{};
    unsigned long long bytes = 0;
    unsigned ops = 0;
    DWORD pid = 0;
};

struct NetKey {
    DWORD pid = 0;
    bool udp = false;
    bool outgoing = false;
    std::wstring ip;
    unsigned port = 0;
    bool operator==(const NetKey& other) const {
        return pid == other.pid && udp == other.udp && outgoing == other.outgoing &&
               port == other.port && ip == other.ip;
    }
};

struct NetKeyHash {
    size_t operator()(const NetKey& key) const {
        size_t h = std::hash<std::wstring>()(key.ip);
        h ^= static_cast<size_t>(key.pid) * 1315423911u;
        h ^= static_cast<size_t>(key.port) << 1;
        h ^= (key.udp ? 0x11u : 0x23u) | (key.outgoing ? 0x41u : 0x83u);
        return h;
    }
};

struct NetAggregate {
    FILETIME first{};
    FILETIME last{};
    unsigned long long bytes = 0;
    unsigned ops = 0;
    DWORD pid = 0;
    bool udp = false;
    bool outgoing = false;
    std::wstring ip;
    unsigned port = 0;
    std::wstring host;
};

} // namespace

struct Monitor::Impl {
    std::wstring targetPath;
    std::wstring extension;
    std::atomic<bool> active{ false };
    std::atomic<bool> stopping{ false };
    std::atomic<DWORD> rootPid{ 0 };
    std::atomic<int> activeUserProcesses{ 0 };
    std::atomic<unsigned long long> droppedEvents{ 0 };
    std::atomic<bool> targetRunning{ false };

    EtwSession kernelSession;
    EtwSession userSession;
    std::thread processThread;
    std::thread flushThread;
    HANDLE processWake = nullptr;
    std::atomic<bool> threadsStop{ false };

    mutable std::mutex statusMutex;
    std::wstring status = L"Ожидание";

    std::mutex queueMutex;
    std::deque<LogEvent> events;

    std::mutex procMutex;
    mutable std::shared_mutex watchMutex;
    std::unordered_set<DWORD> watchedPids;
    std::unordered_map<DWORD, ProcessNode> processes;
    std::unordered_set<DWORD> specialHostPids;
    std::vector<std::wstring> serviceNames;
    std::unordered_map<DWORD, std::wstring> serviceNameByPid;

    mutable std::mutex actorMutex;
    std::unordered_map<DWORD, std::wstring> actorCache;

    std::unordered_map<uint64_t, FileRef> fileObjects;
    std::unordered_map<uint64_t, FileRef> fileKeys;

    std::mutex writeMutex;
    std::unordered_map<WriteKey, WriteAggregate, WriteKeyHash> pendingWrites;

    std::mutex netMutex;
    std::unordered_map<NetKey, NetAggregate, NetKeyHash> pendingNetwork;
    std::shared_mutex dnsMutex;
    std::unordered_map<std::wstring, std::wstring> ipToHost;
    std::unordered_set<std::wstring> localIps;
    std::unordered_map<std::wstring, ULONGLONG> recentRegistryEvents;
    std::unordered_map<std::wstring, ULONGLONG> recentWebUrls;
    FILETIME sessionStartTime{};
    std::unordered_set<std::wstring> reportedCreatedPaths;
    std::unordered_set<std::wstring> knownDirectories;

    std::vector<std::wstring> warnings;

    void QueueEvent(const LogEvent& event) {
        if (events.size() > 100000) {
            ++droppedEvents;
            return;
        }
        std::lock_guard<std::mutex> lock(queueMutex);
        if (events.size() > 100000) {
            ++droppedEvents;
            return;
        }
        events.push_back(event);
    }

    void QueueSimple(EventCategory category, const std::wstring& action,
                     const std::wstring& object, const std::wstring& details,
                     FILETIME when, bool underline = false) {
        LogEvent event;
        event.time = when;
        event.category = category;
        event.action = action;
        event.object = object;
        event.details = details;
        event.underline = underline;
        QueueEvent(event);
    }

    void SetStatus(const std::wstring& value) {
        std::lock_guard<std::mutex> lock(statusMutex);
        status = value;
    }

    std::wstring ActorFor(DWORD pid) {
        if (pid == 0) return L"PID 0";
        {
            std::lock_guard<std::mutex> lock(actorMutex);
            auto it = actorCache.find(pid);
            if (it != actorCache.end()) return it->second;
        }
        std::wstring name = GetProcessName(pid);
        std::wstring result = L"PID " + FormatPid(pid);
        if (!name.empty() && name != L"процесс") result += L" · " + name;
        {
            std::lock_guard<std::mutex> lock(actorMutex);
            if (actorCache.size() > 1024) actorCache.clear();
            actorCache[pid] = result;
        }
        return result;
    }

    bool IsWatched(DWORD pid) const {
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return false;
        std::shared_lock<std::shared_mutex> lock(watchMutex);
        return watchedPids.find(pid) != watchedPids.end();
    }

    std::wstring LookupHost(const std::wstring& ip) {
        std::shared_lock<std::shared_mutex> lock(dnsMutex);
        auto it = ipToHost.find(ip);
        if (it == ipToHost.end()) return ip;
        return it->second;
    }

    void RememberHost(const std::wstring& ip, const std::wstring& host) {
        if (ip.empty() || host.empty()) return;
        std::unique_lock<std::shared_mutex> lock(dnsMutex);
        if (ipToHost.size() > 12000) ipToHost.clear();
        ipToHost[ip] = host;
    }

    void FlushWritesNow(const std::wstring& onlyPath = L"") {
        std::vector<std::pair<WriteKey, WriteAggregate>> batch;
        {
            std::lock_guard<std::mutex> lock(writeMutex);
            if (onlyPath.empty()) {
                for (auto& item : pendingWrites) batch.emplace_back(item.first, item.second);
                pendingWrites.clear();
            } else {
                for (auto it = pendingWrites.begin(); it != pendingWrites.end();) {
                    if (it->first.path == onlyPath) {
                        batch.emplace_back(it->first, it->second);
                        it = pendingWrites.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }
        std::sort(batch.begin(), batch.end(), [](const auto& a, const auto& b) {
            return FileTimeToU64(a.second.first) < FileTimeToU64(b.second.first);
        });
        for (const auto& item : batch) {
            const std::wstring& path = item.first.path;
            const WriteAggregate& agg = item.second;
            std::wstring details = L"Записано " + FormatBytes(agg.bytes) +
                                   L" (" + std::to_wstring(agg.ops) + L" операций) · " +
                                   ActorFor(item.first.pid);
            QueueSimple(CatFile, L"Изменён файл", path, details, agg.first);
        }
    }

    void FlushNetwork() {
        std::vector<NetAggregate> batch;
        {
            std::lock_guard<std::mutex> lock(netMutex);
            for (auto& item : pendingNetwork) batch.push_back(item.second);
            pendingNetwork.clear();
        }
        std::sort(batch.begin(), batch.end(), [](const NetAggregate& a, const NetAggregate& b) {
            return FileTimeToU64(a.first) < FileTimeToU64(b.first);
        });
        for (const auto& agg : batch) {
            if (agg.bytes == 0) continue;
            std::wstring host = agg.host.empty() ? LookupHost(agg.ip) : agg.host;
            std::wstring url = BuildUrl(host, agg.port, agg.udp);
            std::wstring details;
            if (agg.outgoing) details = L"Передано " + FormatBytes(agg.bytes);
            else details = L"Получено " + FormatBytes(agg.bytes);
            details += L" (" + std::to_wstring(agg.ops) + L" операций)";
            if (host != agg.ip) details += L" · узел " + FormatEndpoint(agg.ip, agg.port);
            details += L" · " + ActorFor(agg.pid);
            QueueSimple(CatNetwork, agg.outgoing ? L"Передача данных" : L"Приём данных",
                        url, details, agg.first);
        }
    }

    std::wstring FilePathFromObject(ULONGLONG fileObject, ULONGLONG fileKey, bool* isDir) {
        auto it = fileObjects.find(fileObject);
        if (it != fileObjects.end()) {
            if (isDir) *isDir = it->second.isDir;
            return it->second.path;
        }
        auto kit = fileKeys.find(fileKey);
        if (kit != fileKeys.end()) {
            if (isDir) *isDir = kit->second.isDir;
            return kit->second.path;
        }
        if (isDir) *isDir = false;
        return L"";
    }

    void RememberFile(ULONGLONG fileObject, ULONGLONG fileKey, const FileRef& ref) {
        if (fileObjects.size() > 16000) fileObjects.clear();
        if (fileKeys.size() > 16000) fileKeys.clear();
        if (fileObject) fileObjects[fileObject] = ref;
        if (fileKey) fileKeys[fileKey] = ref;
    }

    void ProcessFileEvent(PEVENT_RECORD record) {
        USHORT id = record->EventHeader.EventDescriptor.Id;
        if (id != 12 && id != 16 && id != 26 && id != 27) return;
        DWORD pid = record->EventHeader.ProcessId;
        if (!IsWatched(pid)) return;
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) return;
        FILETIME when = EventTime(record);

        if (id == 12) { // Create/open. Distinguish genuinely new entries by creation time.
            ULONGLONG fileObject = 0;
            DWORD attributes = 0;
            std::wstring fileName;
            decoder.GetUInt64(L"FileObject", fileObject);
            if (!decoder.GetUInt32(L"CreateAttributes", attributes)) decoder.GetUInt32(L"FileAttributes", attributes);
            if (!decoder.GetString(L"FileName", fileName)) return;
            std::wstring path = NormalizeNtPath(fileName);
            if (path.empty() || IsInstrumentationNoisePath(path)) return;
            WIN32_FILE_ATTRIBUTE_DATA data = {};
            bool hasData = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) != FALSE;
            bool isDir = hasData ? IsDirectoryAttribute(data.dwFileAttributes)
                                 : IsDirectoryAttribute(attributes);
            if (isDir) knownDirectories.insert(path);
            FileRef ref{ path, isDir };
            RememberFile(fileObject, 0, ref);

            if (reportedCreatedPaths.find(path) != reportedCreatedPaths.end()) return;
            if (!hasData) return;
            ULONGLONG created = FileTimeToU64(data.ftCreationTime);
            ULONGLONG sessionStart = FileTimeToU64(sessionStartTime);
            if (created + 20000000ull < sessionStart) return; // existed before this session
            if (reportedCreatedPaths.size() > 20000) reportedCreatedPaths.clear();
            reportedCreatedPaths.insert(path);
            QueueSimple(CatFile, isDir ? L"Создана папка" : L"Создан файл",
                        path, ActorFor(pid), when);
            return;
        }
        if (id == 16) { // Write
            ULONGLONG fileObject = 0, fileKey = 0;
            DWORD ioSize = 0;
            decoder.GetUInt64(L"FileObject", fileObject);
            decoder.GetUInt64(L"FileKey", fileKey);
            decoder.GetUInt32(L"IOSize", ioSize);
            bool isDir = false;
            std::wstring path = FilePathFromObject(fileObject, fileKey, &isDir);
            if (path.empty() || IsInstrumentationNoisePath(path)) return;
            if (fileKey) {
                FileRef ref{ path, isDir };
                if (fileKeys.size() > 16000) fileKeys.clear();
                fileKeys[fileKey] = ref;
            }
            if (isDir) return;
            if (ioSize == 0) return;
            {
                std::lock_guard<std::mutex> lock(writeMutex);
                WriteKey key{ path, pid };
                auto it = pendingWrites.find(key);
                if (it == pendingWrites.end()) {
                    WriteAggregate agg;
                    agg.first = when;
                    agg.last = when;
                    agg.bytes = ioSize;
                    agg.ops = 1;
                    agg.pid = pid;
                    if (pendingWrites.size() > 20000) pendingWrites.clear();
                    pendingWrites.emplace(key, agg);
                } else {
                    it->second.last = when;
                    it->second.bytes += ioSize;
                    ++it->second.ops;
                }
            }
            return;
        }
        if (id == 26) { // DeletePath
            std::wstring filePath;
            ULONGLONG fileObject = 0, fileKey = 0;
            decoder.GetString(L"FilePath", filePath);
            decoder.GetUInt64(L"FileObject", fileObject);
            decoder.GetUInt64(L"FileKey", fileKey);
            bool isDir = false;
            std::wstring known = FilePathFromObject(fileObject, fileKey, &isDir);
            std::wstring path = !filePath.empty() ? NormalizeNtPath(filePath) : known;
            if (path.empty() || IsInstrumentationNoisePath(path)) return;
            if (!isDir && knownDirectories.find(path) != knownDirectories.end()) isDir = true;
            FlushWritesNow(path);
            std::wstring action = isDir ? L"Удалена папка" : L"Удалён файл";
            QueueSimple(CatFile, action, path, ActorFor(pid), when);
            reportedCreatedPaths.erase(path);
            knownDirectories.erase(path);
            fileObjects.erase(fileObject);
            fileKeys.erase(fileKey);
            return;
        }
        if (id == 27) { // RenamePath
            std::wstring newPathRaw;
            ULONGLONG fileObject = 0, fileKey = 0;
            decoder.GetString(L"FilePath", newPathRaw);
            decoder.GetUInt64(L"FileObject", fileObject);
            decoder.GetUInt64(L"FileKey", fileKey);
            bool isDir = false;
            std::wstring oldPath = FilePathFromObject(fileObject, fileKey, &isDir);
            if (!isDir && knownDirectories.find(oldPath) != knownDirectories.end()) isDir = true;
            std::wstring newPath = NormalizeNtPath(newPathRaw);
            if (newPath.empty()) newPath = oldPath;
            if (oldPath.empty() || IsInstrumentationNoisePath(oldPath) || IsInstrumentationNoisePath(newPath)) return;
            FlushWritesNow(oldPath);
            std::wstring details = ActorFor(pid);
            if (!newPath.empty() && newPath != oldPath) details += L" · было: " + oldPath;
            QueueSimple(CatFile, L"Переименован или перемещён", newPath, details, when);
            reportedCreatedPaths.erase(oldPath);
            knownDirectories.erase(oldPath);
            if (isDir) knownDirectories.insert(newPath);
            FileRef ref{ newPath, isDir };
            RememberFile(fileObject, fileKey, ref);
            return;
        }
    }

    void ProcessRegistryEvent(PEVENT_RECORD record) {
        USHORT id = record->EventHeader.EventDescriptor.Id;
        if (id != 1 && id != 3 && id != 5 && id != 6 && id != 11 && id != 15) return;
        DWORD pid = record->EventHeader.ProcessId;
        if (!IsWatched(pid)) return;
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) return;
        FILETIME when = EventTime(record);
        DWORD status = 0;
        if (decoder.GetUInt32(L"Status", status) && status != 0 && id != 1) return;
        std::wstring base, relative, keyName, valueName;
        decoder.GetString(L"BaseName", base);
        decoder.GetString(L"RelativeName", relative);
        decoder.GetString(L"KeyName", keyName);
        decoder.GetString(L"ValueName", valueName);
        std::wstring key = ComposeRegistryKey(base, relative);
        if (!keyName.empty()) keyName = NormalizeRegistryPath(keyName);
        if (keyName.empty()) keyName = key;
        if (keyName.empty()) return;

        std::wstring dedupKey = std::to_wstring(id) + L"|" + keyName + L"|" + valueName;
        ULONGLONG nowTick = GetTickCount64();
        auto recent = recentRegistryEvents.find(dedupKey);
        if (recent != recentRegistryEvents.end() && nowTick - recent->second < 900) return;
        if (recentRegistryEvents.size() > 4000) recentRegistryEvents.clear();
        recentRegistryEvents[dedupKey] = nowTick;

        if (id == 1) { // CreateKey
            DWORD disposition = 0;
            decoder.GetUInt32(L"Disposition", disposition);
            if (disposition == 2) return; // opened existing
            QueueSimple(CatRegistry, L"Создан раздел реестра", keyName, ActorFor(pid), when);
            return;
        }
        if (id == 3) {
            QueueSimple(CatRegistry, L"Удалён раздел реестра", keyName, ActorFor(pid), when);
            return;
        }
        if (id == 5) { // SetValueKey
            DWORD type = 0;
            std::vector<BYTE> data;
            decoder.GetUInt32(L"Type", type);
            decoder.GetBinary(L"CapturedData", data);
            std::wstring object = keyName;
            if (!valueName.empty()) object += L"\\" + valueName;
            else object += L"\\ (По умолчанию)";
            std::wstring details = RegTypeName(type) + L": " + RegDataText(type, data) + L" · " + ActorFor(pid);
            QueueSimple(CatRegistry, L"Изменён параметр реестра", object, details, when);
            return;
        }
        if (id == 6) {
            std::wstring object = keyName;
            if (!valueName.empty()) object += L"\\" + valueName;
            QueueSimple(CatRegistry, L"Удалён параметр реестра", object, ActorFor(pid), when);
            return;
        }
        if (id == 11 || id == 15) {
            QueueSimple(CatRegistry, id == 11 ? L"Изменены параметры раздела" : L"Изменены права раздела",
                        keyName, ActorFor(pid), when);
        }
    }

    void AddNetworkAggregate(DWORD pid, bool udp, bool outgoing, const std::wstring& ip,
                             unsigned port, unsigned size, FILETIME when, const std::wstring& host) {
        if (!IsWatched(pid) || size == 0) return;
        std::lock_guard<std::mutex> lock(netMutex);
        NetKey key{ pid, udp, outgoing, ip, port };
        auto it = pendingNetwork.find(key);
        if (it == pendingNetwork.end()) {
            NetAggregate agg;
            agg.first = when;
            agg.last = when;
            agg.bytes = size;
            agg.ops = 1;
            agg.pid = pid;
            agg.udp = udp;
            agg.outgoing = outgoing;
            agg.ip = ip;
            agg.port = port;
            agg.host = host;
            if (pendingNetwork.size() > 12000) pendingNetwork.clear();
            pendingNetwork.emplace(key, agg);
        } else {
            it->second.last = when;
            it->second.bytes += size;
            ++it->second.ops;
            if (it->second.host.empty()) it->second.host = host;
        }
    }

    void ProcessNetworkEvent(PEVENT_RECORD record) {
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) {
            return;
        }
        DWORD pid = 0;
        if (!decoder.GetUInt32(L"PID", pid)) pid = record->EventHeader.ProcessId;
        if (!IsWatched(pid)) {
            return;
        }
        USHORT id = record->EventHeader.EventDescriptor.Id;
        bool udp = false;
        bool outgoing = false;
        bool connectEvent = false;
        bool disconnectEvent = false;
        bool acceptEvent = false;
        bool retransmit = false;
        switch (id) {
            case 10: case 26: outgoing = true; break;       // TCP send v4/v6
            case 11: case 27: outgoing = false; break;      // TCP recv v4/v6
            case 12: case 28: connectEvent = true; break;   // connect
            case 13: case 29: disconnectEvent = true; break;
            case 15: case 31: acceptEvent = true; break;    // accepted
            case 16: case 32: connectEvent = true; break;   // reconnect
            case 42: case 58: outgoing = true; udp = true; break;
            case 43: case 59: outgoing = false; udp = true; break;
            case 14: case 30: retransmit = true; break;
            default: return;
        }
        (void)retransmit;
        DWORD size = 0;
        DWORD dport = 0, sport = 0;
        std::vector<BYTE> daddr, saddr;
        decoder.GetUInt32(L"size", size);
        decoder.GetUInt32(L"dport", dport);
        decoder.GetUInt32(L"sport", sport);
        dport = ((dport & 0xFF) << 8) | ((dport >> 8) & 0xFF);
        sport = ((sport & 0xFF) << 8) | ((sport >> 8) & 0xFF);
        if (dport > 65535) dport = 0;
        if (sport > 65535) sport = 0;
        decoder.GetBinary(L"daddr", daddr);
        decoder.GetBinary(L"saddr", saddr);
        std::wstring dip = daddr.size() == 4 ? FormatIpv4(*reinterpret_cast<DWORD*>(daddr.data()))
                          : (daddr.size() == 16 ? FormatIpv6(daddr.data()) : L"");
        std::wstring sip = saddr.size() == 4 ? FormatIpv4(*reinterpret_cast<DWORD*>(saddr.data()))
                          : (saddr.size() == 16 ? FormatIpv6(saddr.data()) : L"");
        if (dip.empty() && sip.empty()) return;
        std::wstring ip;
        unsigned port = 0;
        bool daddrLocal = localIps.find(dip) != localIps.end();
        bool saddrLocal = localIps.find(sip) != localIps.end();
        if (!dip.empty() && !sip.empty() && daddrLocal != saddrLocal) {
            if (daddrLocal) {
                ip = sip;
                port = sport;
            } else {
                ip = dip;
                port = dport;
            }
        } else if (outgoing || connectEvent || disconnectEvent) {
            ip = dip;
            port = dport;
        } else {
            ip = sip;
            port = sport;
        }
        if (ip.empty()) { ip = dip.empty() ? sip : dip; port = dip.empty() ? sport : dport; }
        std::wstring host = LookupHost(ip);
        FILETIME when = EventTime(record);
        if (connectEvent || disconnectEvent || acceptEvent) {
            std::wstring url = BuildUrl(host, port, udp);
            std::wstring action;
            if (acceptEvent) action = L"Входящее соединение";
            else if (disconnectEvent) action = L"Соединение закрыто";
            else action = L"Сетевое подключение";
            std::wstring details = FormatEndpoint(ip, port);
            if (host != ip) details += L" (" + host + L")";
            details += L" · " + ActorFor(pid);
            QueueSimple(CatNetwork, action, url, details, when);
        } else {
            AddNetworkAggregate(pid, udp, outgoing, ip, port, size, when, host);
        }
    }

    void ProcessTaskEvent(PEVENT_RECORD record) {
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) return;
        USHORT id = record->EventHeader.EventDescriptor.Id;
        std::wstring action;
        switch (id) {
            case 106: action = L"Задача создана"; break;
            case 140: action = L"Задача изменена"; break;
            case 141: action = L"Задача удалена"; break;
            case 142: action = L"Задача отключена"; break;
            case 111: action = L"Задача остановлена"; break;
            case 200: action = L"Задача запущена"; break;
            case 201: action = L"Действие задачи завершено"; break;
            default: return;
        }
        std::wstring taskName, user, actionName;
        decoder.GetString(L"TaskName", taskName);
        decoder.GetString(L"UserContext", user);
        if (!decoder.GetString(L"UserName", user)) decoder.GetString(L"UserContext", user);
        decoder.GetString(L"ActionName", actionName);
        if (taskName.empty()) taskName = L"(без имени)";
        std::wstring details = L"Планировщик заданий";
        if (!user.empty()) details += L" · пользователь: " + user;
        if (!actionName.empty()) details += L" · действие: " + actionName;
        FILETIME when = EventTime(record);
        QueueSimple(CatTasks, action, taskName, details, when);
    }

    void ProcessDnsEvent(PEVENT_RECORD record) {
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) return;
        USHORT id = record->EventHeader.EventDescriptor.Id;
        if (id != 3008 && id != 3018 && id != 3020) return;
        std::wstring queryName, results;
        decoder.GetString(L"QueryName", queryName);
        decoder.GetString(L"QueryResults", results);
        if (queryName.empty()) return;
        std::vector<std::wstring> ips;
        std::wstring token;
        auto flush = [&]() {
            if (token.empty()) return;
            bool looksV4 = token.find(L'.') != std::wstring::npos;
            bool allDigitsOrDot = true;
            for (wchar_t c : token) {
                if (!(iswdigit(c) || c == L'.')) { allDigitsOrDot = false; break; }
            }
            bool looksV6 = token.find(L':') != std::wstring::npos;
            if (looksV4 && allDigitsOrDot) {
                ips.push_back(token);
                RememberHost(token, queryName);
            } else if (looksV6 && token.size() > 2) {
                ips.push_back(token);
                RememberHost(token, queryName);
            }
            token.clear();
        };
        for (wchar_t c : results) {
            if (iswspace(c) || c == L',' || c == L';' || c == L'[' || c == L']' ||
                c == L'\n' || c == L'\r' || c == L'\t') {
                flush();
            } else {
                token += c;
            }
        }
        flush();
        DWORD pid = record->EventHeader.ProcessId;
        if (!IsWatched(pid)) return;
        std::wstring details;
        if (!ips.empty()) {
            details = L"Адрес: ";
            for (size_t i = 0; i < ips.size() && i < 6; ++i) {
                if (i) details += L", ";
                details += ips[i];
            }
            details += L" · ";
        }
        details += ActorFor(pid);
        FILETIME when = EventTime(record);
        QueueSimple(CatNetwork, L"DNS-запрос", queryName, details, when);
    }

    void OnKernelRecord(PEVENT_RECORD record) {
        if (!record) return;
        if (IsEqualGUID(record->EventHeader.ProviderId, kKernelFile)) ProcessFileEvent(record);
        else if (IsEqualGUID(record->EventHeader.ProviderId, kKernelRegistry)) ProcessRegistryEvent(record);
        else if (IsEqualGUID(record->EventHeader.ProviderId, kKernelNetwork)) ProcessNetworkEvent(record);
    }

    void ProcessUrlEvent(PEVENT_RECORD record) {
        DWORD pid = record->EventHeader.ProcessId;
        if (!IsWatched(pid)) return;
        EtwEventDecoder decoder(record);
        if (!decoder.IsValid()) return;
        std::wstring url;
        std::wstring fieldName;
        if (!decoder.FindUrl(url, fieldName)) return;
        if (url.size() < 8) return;
        ULONGLONG nowTick = GetTickCount64();
        auto found = recentWebUrls.find(url);
        if (found != recentWebUrls.end() && nowTick - found->second < 700) return;
        if (recentWebUrls.size() > 4000) recentWebUrls.clear();
        recentWebUrls[url] = nowTick;
        std::wstring providerName = L"WinINet";
        if (IsEqualGUID(record->EventHeader.ProviderId, kWinHttp)) providerName = L"WinHTTP";
        else if (IsEqualGUID(record->EventHeader.ProviderId, kWinInetCapture)) providerName = L"WinINet Capture";
        std::wstring details = providerName + L" · " + ActorFor(pid);
        FILETIME when = EventTime(record);
        QueueSimple(CatNetwork, L"Веб-запрос", url, details, when);
    }

    void OnUserRecord(PEVENT_RECORD record) {
        if (!record) return;
        if (IsEqualGUID(record->EventHeader.ProviderId, kTaskScheduler)) ProcessTaskEvent(record);
        else if (IsEqualGUID(record->EventHeader.ProviderId, kDnsClient)) ProcessDnsEvent(record);
        else if (IsEqualGUID(record->EventHeader.ProviderId, kWinInet) ||
                 IsEqualGUID(record->EventHeader.ProviderId, kWinInetCapture) ||
                 IsEqualGUID(record->EventHeader.ProviderId, kWinHttp)) {
            ProcessUrlEvent(record);
        }
    }

    DWORD QueryServicePid(const std::wstring& serviceName) {
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager) return 0;
        SC_HANDLE service = OpenServiceW(manager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        DWORD pid = 0;
        if (service) {
            SERVICE_STATUS_PROCESS status = {};
            DWORD needed = 0;
            if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
                if (status.dwCurrentState == SERVICE_RUNNING) pid = status.dwProcessId;
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
        return pid;
    }

    void RefreshServices() {
        std::vector<std::wstring> services;
        {
            std::lock_guard<std::mutex> lock(procMutex);
            services = serviceNames;
        }
        for (const auto& name : services) {
            DWORD pid = QueryServicePid(name);
            if (!pid) continue;
            std::lock_guard<std::mutex> lock(procMutex);
            if (specialHostPids.find(pid) != specialHostPids.end()) continue;
            specialHostPids.insert(pid);
            serviceNameByPid[pid] = name;
            ProcessNode node;
            node.pid = pid;
            node.special = true;
            node.startReported = true;
            node.name = GetProcessName(pid);
            node.path = GetProcessPath(pid);
            node.created = NowFileTime();
            node.handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            processes[pid] = node;
            std::unique_lock<std::shared_mutex> watch(watchMutex);
            watchedPids.insert(pid);
        }
    }

    void AddProcessCandidate(const PROCESSENTRY32W& entry,
                             std::unordered_map<DWORD, PROCESSENTRY32W>& snapshot) {
        DWORD pid = entry.th32ProcessID;
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return;
        if (processes.find(pid) != processes.end()) return;
        DWORD cursor = entry.th32ParentProcessID;
        bool related = false;
        for (int depth = 0; depth < 64 && cursor; ++depth) {
            if (processes.find(cursor) != processes.end()) { related = true; break; }
            auto it = snapshot.find(cursor);
            if (it == snapshot.end()) break;
            cursor = it->second.th32ParentProcessID;
        }
        if (!related) return;
        ProcessNode node;
        node.pid = pid;
        node.parentPid = entry.th32ParentProcessID;
        node.name = entry.szExeFile;
        // conhost is an automatic helper of every console program and generates enormous
        // amounts of unrelated DLL/file activity. Do not attach it to the target tree.
        if (_wcsicmp(node.name.c_str(), L"conhost.exe") == 0) return;
        node.path = GetProcessPath(pid);
        if (node.path.empty()) node.path = node.name;
        node.handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        FILETIME created = NowFileTime();
        if (node.handle) {
            FILETIME exitTime{}, kernelTime{}, userTime{};
            if (GetProcessTimes(node.handle, &created, &exitTime, &kernelTime, &userTime)) {
                node.created = created;
            }
        }
        node.created = created;
        node.active = true;
        if (processes.size() > 8000) return;
        processes[pid] = node;
        {
            std::unique_lock<std::shared_mutex> watch(watchMutex);
            watchedPids.insert(pid);
        }
        std::wstring details = L"PID " + FormatPid(pid) + L" · родитель: " +
                               ParentInfo(snapshot, entry.th32ParentProcessID);
        QueueSimple(CatProcess, L"Запущен процесс", node.path, details, node.created);
    }

    void ProcessWatcher() {
        ULONGLONG lastServiceRefresh = 0;
        while (!threadsStop.load()) {
            WaitForSingleObject(processWake, 100);
            if (threadsStop.load()) break;
            ULONGLONG nowTick = GetTickCount64();
            if (nowTick - lastServiceRefresh > 900) {
                RefreshServices();
                lastServiceRefresh = nowTick;
            }
            HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshotHandle == INVALID_HANDLE_VALUE) continue;
            std::unordered_map<DWORD, PROCESSENTRY32W> snapshot;
            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snapshotHandle, &entry)) {
                do {
                    snapshot[entry.th32ProcessID] = entry;
                } while (Process32NextW(snapshotHandle, &entry));
            }
            CloseHandle(snapshotHandle);

            {
                std::lock_guard<std::mutex> lock(procMutex);
                for (auto& item : snapshot) {
                    AddProcessCandidate(item.second, snapshot);
                }
                for (auto it = processes.begin(); it != processes.end();) {
                    ProcessNode& node = it->second;
                    bool stillThere = snapshot.find(node.pid) != snapshot.end();
                    bool signaled = node.handle && WaitForSingleObject(node.handle, 0) == WAIT_OBJECT_0;
                    if (!stillThere || signaled) {
                        DWORD exitCode = 0;
                        if (node.handle) {
                            GetExitCodeProcess(node.handle, &exitCode);
                            CloseHandle(node.handle);
                            node.handle = nullptr;
                        }
                        if (!node.special) {
                            bool isRoot = node.pid == rootPid.load();
                            std::wstring details = L"PID " + FormatPid(node.pid) + L" · код завершения " +
                                                   std::to_wstring(exitCode);
                            if (isRoot) {
                                details += L" · слежка за запущенными процессами продолжается";
                                QueueSimple(CatProcess, L"Основной файл закрыт", node.path,
                                            details, NowFileTime(), true);
                            } else {
                                QueueSimple(CatProcess, L"Завершён процесс", node.path, details, NowFileTime());
                            }
                        }
                        it = processes.erase(it);
                    } else {
                        ++it;
                    }
                }
                int count = 0;
                for (const auto& item : processes) {
                    if (!item.second.special) ++count;
                }
                activeUserProcesses = count;
                targetRunning = count > 0;
            }
        }
    }

    void FlushWorker() {
        while (!threadsStop.load()) {
            WaitForSingleObject(processWake, 450);
            if (threadsStop.load()) break;
            FlushWritesNow();
            FlushNetwork();
        }
    }

    bool StartSessions(std::wstring& error) {
        std::wstring sessionError;
        if (!kernelSession.Start(MakeSessionName(L"Kernel"), true, sessionError)) {
            error = sessionError + L"\n\nЗапустите WatchProg обычным способом и подтвердите запрос прав администратора. Если другой анализатор (Process Monitor, WPR, Sysinternals) уже использует системный журнал, закройте его.";
            return false;
        }
        if (!kernelSession.EnableProvider(kKernelFile, 4, kFileKeywords, 0, sessionError) ||
            !kernelSession.EnableProvider(kKernelRegistry, 4, kRegistryKeywords, 0, sessionError) ||
            !kernelSession.EnableProvider(kKernelNetwork, 4, kNetworkKeywords, 0, sessionError)) {
            error = sessionError;
            kernelSession.Stop();
            return false;
        }
        if (!kernelSession.BeginConsume([](PEVENT_RECORD record) {
                try {
                    auto* self = static_cast<Impl*>(record->UserContext);
                    if (self) self->OnKernelRecord(record);
                } catch (...) {}
            }, this, sessionError)) {
            error = sessionError;
            kernelSession.Stop();
            return false;
        }

        bool taskOk = false, dnsOk = false, urlOk = false;
        if (userSession.Start(MakeSessionName(L"User"), false, sessionError)) {
            if (userSession.EnableProvider(kTaskScheduler, 4, 0, 0, sessionError)) taskOk = true;
            if (userSession.EnableProvider(kDnsClient, 4, 0, 0, sessionError)) dnsOk = true;
            if (userSession.EnableProvider(kWinInet, 5, 0, 0, sessionError)) urlOk = true;
            if (userSession.EnableProvider(kWinHttp, 5, 0, 0, sessionError)) urlOk = true;
            if (userSession.EnableProvider(kWinInetCapture, 5, 0, 0, sessionError)) urlOk = true;
            if ((taskOk || dnsOk || urlOk) && !userSession.BeginConsume([](PEVENT_RECORD record) {
                    try {
                        auto* self = static_cast<Impl*>(record->UserContext);
                        if (self) self->OnUserRecord(record);
                    } catch (...) {}
                }, this, sessionError)) {
                userSession.Stop();
                taskOk = dnsOk = urlOk = false;
            }
        }
        if (!taskOk) {
            warnings.push_back(L"Не удалось включить журнал планировщика заданий. События задач могут отсутствовать.");
        }
        if (!dnsOk) {
            warnings.push_back(L"Не удалось включить журнал DNS. В сетевых событиях останутся только IP-адреса.");
        }
        if (!urlOk) {
            warnings.push_back(L"Не удалось включить журнал WinINet/WinHTTP. Точные URL могут быть недоступны.");
        }
        return true;
    }

    void EmitWarnings(FILETIME when) {
        for (const auto& warning : warnings) {
            QueueSimple(CatSystem, L"Предупреждение", L"Ограничение наблюдения", warning, when);
        }
        warnings.clear();
    }

    void CleanupThreads() {
        threadsStop = true;
        if (processWake) SetEvent(processWake);
        if (processThread.joinable()) processThread.join();
        if (flushThread.joinable()) flushThread.join();
        if (processWake) {
            CloseHandle(processWake);
            processWake = nullptr;
        }
    }

    void ResetState() {
        std::lock_guard<std::mutex> lock(procMutex);
        for (auto& item : processes) {
            if (item.second.handle) CloseHandle(item.second.handle);
        }
        processes.clear();
        specialHostPids.clear();
        serviceNameByPid.clear();
        {
            std::unique_lock<std::shared_mutex> watch(watchMutex);
            watchedPids.clear();
        }
        {
            std::lock_guard<std::mutex> actor(actorMutex);
            actorCache.clear();
        }
        fileObjects.clear();
        fileKeys.clear();
        {
            std::lock_guard<std::mutex> write(writeMutex);
            pendingWrites.clear();
        }
        {
            std::lock_guard<std::mutex> net(netMutex);
            pendingNetwork.clear();
        }
        {
            std::unique_lock<std::shared_mutex> dns(dnsMutex);
            ipToHost.clear();
        }
        {
            std::lock_guard<std::mutex> queue(queueMutex);
            events.clear();
        }
        rootPid = 0;
        activeUserProcesses = 0;
        targetRunning = false;
        threadsStop = false;
        sessionStartTime = {};
        reportedCreatedPaths.clear();
        knownDirectories.clear();
        recentRegistryEvents.clear();
        recentWebUrls.clear();
        droppingReset();
    }

    void droppingReset() { droppedEvents = 0; }

    ~Impl() {
        Stop();
        CleanupThreads();
    }

    void Stop() {
        if (!active.exchange(false)) return;
        stopping = true;
        threadsStop = true;
        if (processWake) SetEvent(processWake);
        if (processThread.joinable()) processThread.join();
        if (flushThread.joinable()) flushThread.join();
        kernelSession.Stop();
        userSession.Stop();
        FlushWritesNow();
        FlushNetwork();
        rootPid = 0;
        activeUserProcesses = 0;
        targetRunning = false;
        SetStatus(L"Остановлено");
        QueueSimple(CatSystem, L"Наблюдение остановлено", L"Сеанс завершён",
                    L"Запись новых действий прекращена.", NowFileTime());
        if (processWake) {
            CloseHandle(processWake);
            processWake = nullptr;
        }
        stopping = false;
    }
};

Monitor::Monitor() : impl_(std::make_unique<Impl>()) {}
Monitor::~Monitor() = default;

bool Monitor::Start(const std::wstring& targetPath, const std::wstring& extension, std::wstring& error) {
    Impl& m = *impl_;
    m.Stop();
    m.ResetState();
    m.targetPath = targetPath;
    m.extension = extension;
    m.warnings.clear();
    m.sessionStartTime = NowFileTime();
    m.localIps.clear();
    for (const auto& ip : LocalIpAddresses()) m.localIps.insert(ip);

    if (extension == L".msi") {
        m.serviceNames = { L"msiserver" };
    } else if (extension == L".appx" || extension == L".msix" || extension == L".msixbundle" ||
               extension == L".appxbundle" || extension == L".appinstaller") {
        m.serviceNames = { L"AppXSvc", L"ClipSVC" };
    } else {
        m.serviceNames.clear();
    }

    if (!m.StartSessions(error)) {
        m.SetStatus(L"Ошибка запуска ETW");
        return false;
    }
    m.processWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!m.processWake) {
        error = L"Не удалось создать объект синхронизации: " + FormatWinError(GetLastError());
        m.kernelSession.Stop();
        m.userSession.Stop();
        return false;
    }
    m.active = true;
    m.threadsStop = false;
    m.processThread = std::thread([&m]() { m.ProcessWatcher(); });
    m.flushThread = std::thread([&m]() { m.FlushWorker(); });
    m.SetStatus(L"Наблюдение");
    m.EmitWarnings(NowFileTime());
    return true;
}

void Monitor::AttachRoot(DWORD pid) {
    Impl& m = *impl_;
    if (!m.active || !pid) return;
    m.rootPid = pid;
    ProcessNode node;
    node.pid = pid;
    node.active = true;
    node.startReported = true;
    node.path = m.targetPath;
    node.name = FileNameOf(m.targetPath);
    node.created = NowFileTime();
    node.handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (node.handle) {
        FILETIME exitTime{}, kernelTime{}, userTime{};
        FILETIME created = {};
        if (GetProcessTimes(node.handle, &created, &exitTime, &kernelTime, &userTime)) {
            node.created = created;
        }
    }
    {
        std::lock_guard<std::mutex> lock(m.procMutex);
        m.processes[pid] = node;
    }
    {
        std::unique_lock<std::shared_mutex> watch(m.watchMutex);
        m.watchedPids.insert(pid);
    }
    m.activeUserProcesses = 1;
    m.targetRunning = true;
    std::wstring details = L"PID " + FormatPid(pid) + L" · " + FileNameOf(m.targetPath);
    m.QueueSimple(CatProcess, L"Запуск наблюдаемой программы", m.targetPath, details, node.created);
    m.RefreshServices();
    if (m.processWake) SetEvent(m.processWake);
}

void Monitor::Stop() {
    impl_->Stop();
}

bool Monitor::Active() const {
    return impl_->active;
}

bool Monitor::TargetRunning() const {
    return impl_->targetRunning;
}

DWORD Monitor::RootPid() const {
    return impl_->rootPid;
}

std::vector<LogEvent> Monitor::DrainEvents() {
    std::vector<LogEvent> result;
    Impl& m = *impl_;
    std::lock_guard<std::mutex> lock(m.queueMutex);
    result.reserve(m.events.size());
    while (!m.events.empty()) {
        result.emplace_back(std::move(m.events.front()));
        m.events.pop_front();
    }
    return result;
}

unsigned long long Monitor::DroppedCount() const {
    return impl_->droppedEvents;
}

std::wstring Monitor::StatusText() const {
    Impl& m = *impl_;
    std::lock_guard<std::mutex> lock(m.statusMutex);
    return m.status;
}

