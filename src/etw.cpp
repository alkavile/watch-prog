#include "etw.h"
#include "util.h"

#include <evntprov.h>
#include <tdh.h>
#include <objbase.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <unordered_map>

namespace {

struct SchemaKey {
    GUID provider{};
    USHORT id = 0;
    UCHAR version = 0;
    UCHAR level = 0;
    UCHAR opcode = 0;
    USHORT task = 0;

    bool operator==(const SchemaKey& other) const {
        return id == other.id && version == other.version && level == other.level &&
               opcode == other.opcode && task == other.task &&
               std::memcmp(&provider, &other.provider, sizeof(GUID)) == 0;
    }
};

struct SchemaKeyHash {
    size_t operator()(const SchemaKey& key) const {
        const BYTE* bytes = reinterpret_cast<const BYTE*>(&key);
        size_t hash = 1469598103934665603ull;
        for (size_t i = 0; i < sizeof(SchemaKey); ++i) {
            hash ^= bytes[i];
            hash *= 1099511628211ull;
        }
        return hash;
    }
};

struct CachedSchema {
    std::vector<BYTE> bytes;
};

thread_local std::unordered_map<SchemaKey, std::unique_ptr<CachedSchema>, SchemaKeyHash> g_schemaCache;

PTRACE_EVENT_INFO GetSchema(PEVENT_RECORD event) {
    SchemaKey key;
    key.provider = event->EventHeader.ProviderId;
    key.id = event->EventHeader.EventDescriptor.Id;
    key.version = event->EventHeader.EventDescriptor.Version;
    key.level = event->EventHeader.EventDescriptor.Level;
    key.opcode = event->EventHeader.EventDescriptor.Opcode;
    key.task = event->EventHeader.EventDescriptor.Task;

    auto found = g_schemaCache.find(key);
    if (found != g_schemaCache.end()) {
        return reinterpret_cast<PTRACE_EVENT_INFO>(found->second->bytes.data());
    }

    ULONG size = 0;
    ULONG status = TdhGetEventInformation(event, 0, nullptr, nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) return nullptr;

    auto schema = std::make_unique<CachedSchema>();
    schema->bytes.resize(size);
    status = TdhGetEventInformation(event, 0, nullptr,
                                    reinterpret_cast<PTRACE_EVENT_INFO>(schema->bytes.data()), &size);
    if (status != ERROR_SUCCESS) return nullptr;

    if (g_schemaCache.size() > 512) g_schemaCache.clear();
    auto inserted = g_schemaCache.emplace(key, std::move(schema));
    return reinterpret_cast<PTRACE_EVENT_INFO>(inserted.first->second->bytes.data());
}

} // namespace

EtwSession::~EtwSession() {
    Stop();
}

bool EtwSession::Start(const std::wstring& sessionName, bool systemLogger, std::wstring& error) {
    Stop();
    sessionName_ = sessionName;
    error_.clear();
    const SIZE_T nameBytes = (sessionName.size() + 1) * sizeof(wchar_t);
    const SIZE_T total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes + 64;
    properties_.assign(total, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(total);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2; // FILETIME timestamps
    if (CoCreateGuid(&properties->Wnode.Guid) != S_OK) {
        properties->Wnode.Guid = { 0x8b3f64a1, 0x9d27, 0x4e6c, { 0xa6, 0x31, 0x2b, 0x9b, 0x37, 0x0b, 0x5e, 0x42 } };
    }
    properties->BufferSize = 256;
    properties->MinimumBuffers = 16;
    properties->MaximumBuffers = 192;
    properties->FlushTimer = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    if (systemLogger) properties->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s(reinterpret_cast<wchar_t*>(properties_.data() + sizeof(EVENT_TRACE_PROPERTIES)),
             sessionName.size() + 1, sessionName.c_str());

    ULONG status = StartTraceW(&traceHandle_, sessionName.c_str(), properties);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            ControlTraceW(0, sessionName.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
            status = StartTraceW(&traceHandle_, sessionName.c_str(), properties);
        }
    }
    if (status != ERROR_SUCCESS) {
        traceHandle_ = 0;
        error_ = L"Не удалось запустить сеанс ETW \"" + sessionName + L"\": " + FormatWinError(status);
        error = error_;
        return false;
    }
    active_ = true;
    return true;
}

bool EtwSession::EnableProvider(const GUID& provider, UCHAR level, ULONGLONG anyKeyword,
                                ULONGLONG allKeyword, std::wstring& error) {
    if (!active_) {
        error = L"Сеанс ETW не запущен.";
        return false;
    }
    ULONG status = EnableTraceEx2(traceHandle_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  level, anyKeyword, allKeyword, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        error = L"Не удалось включить поставщика диагностики: " + FormatWinError(status);
        return false;
    }
    return true;
}

bool EtwSession::BeginConsume(EtwCallback callback, void* context, std::wstring& error) {
    if (!active_) {
        error = L"Сеанс ETW не запущен.";
        return false;
    }
    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName = const_cast<LPWSTR>(sessionName_.c_str());
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = callback;
    logFile.Context = context;
    consumerHandle_ = OpenTraceW(&logFile);
    if (consumerHandle_ == INVALID_PROCESSTRACE_HANDLE) {
        DWORD code = GetLastError();
        error = L"Не удалось открыть поток событий ETW: " + FormatWinError(code);
        consumerHandle_ = 0;
        return false;
    }
    consumeDone_ = false;
    consumerThread_ = std::thread([this]() {
        TRACEHANDLE handle = consumerHandle_;
        ProcessTrace(&handle, 1, nullptr, nullptr);
        consumeDone_ = true;
    });
    return true;
}

void EtwSession::Stop() {
    if (!active_) {
        if (consumerThread_.joinable()) consumerThread_.join();
        if (consumerHandle_ && consumerHandle_ != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(consumerHandle_);
            consumerHandle_ = 0;
        }
        return;
    }
    active_ = false;
    if (traceHandle_ != 0) {
        if (!properties_.empty()) {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
            ControlTraceW(0, sessionName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        } else {
            ControlTraceW(traceHandle_, sessionName_.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
        }
        traceHandle_ = 0;
    }
    bool closed = false;
    if (consumerThread_.joinable()) {
        for (int i = 0; i < 150 && !consumeDone_.load(); ++i) Sleep(20);
        if (!consumeDone_.load() && consumerHandle_) {
            CloseTrace(consumerHandle_);
            closed = true;
        }
        consumerThread_.join();
    }
    if (!closed && consumerHandle_ && consumerHandle_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(consumerHandle_);
    }
    consumerHandle_ = 0;
}

EtwEventDecoder::EtwEventDecoder(PEVENT_RECORD event) : event_(event) {
    if (!event_) {
        status_ = ERROR_INVALID_PARAMETER;
        return;
    }
    info_ = GetSchema(event);
    valid_ = info_ != nullptr;
    if (!valid_) status_ = ERROR_NOT_FOUND;
}

bool EtwEventDecoder::Query(const wchar_t* name, std::vector<BYTE>& value) const {
    value.clear();
    if (!valid_ || !name) return false;
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    ULONG size = 0;
    ULONG status = TdhGetPropertySize(event_, 0, nullptr, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size == 0) return false;
    value.resize(size);
    status = TdhGetProperty(event_, 0, nullptr, 1, &descriptor, size, value.data());
    if (status != ERROR_SUCCESS) {
        value.clear();
        return false;
    }
    return true;
}

bool EtwEventDecoder::GetString(const wchar_t* name, std::wstring& value) const {
    std::vector<BYTE> data;
    if (!Query(name, data)) return false;
    size_t chars = data.size() / sizeof(wchar_t);
    if (chars == 0) {
        value.clear();
        return true;
    }
    value.assign(reinterpret_cast<const wchar_t*>(data.data()), chars);
    size_t nullPos = value.find(L'\0');
    if (nullPos != std::wstring::npos) value.resize(nullPos);
    return true;
}

bool EtwEventDecoder::GetUInt32(const wchar_t* name, DWORD& value) const {
    std::vector<BYTE> data;
    if (!Query(name, data) || data.empty()) return false;
    unsigned long long result = 0;
    std::memcpy(&result, data.data(), std::min<size_t>(data.size(), sizeof(result)));
    value = static_cast<DWORD>(result);
    return true;
}

bool EtwEventDecoder::GetUInt64(const wchar_t* name, ULONGLONG& value) const {
    std::vector<BYTE> data;
    if (!Query(name, data) || data.empty()) return false;
    unsigned long long result = 0;
    std::memcpy(&result, data.data(), std::min<size_t>(data.size(), sizeof(result)));
    value = result;
    return true;
}

bool EtwEventDecoder::GetBinary(const wchar_t* name, std::vector<BYTE>& value) const {
    return Query(name, value);
}

bool EtwEventDecoder::HasProperty(const wchar_t* name) const {
    std::vector<BYTE> data;
    return Query(name, data);
}

namespace {

std::wstring ExtractUrl(const std::wstring& value) {
    static const wchar_t* schemes[] = { L"https://", L"http://", L"wss://", L"ws://", L"ftp://" };
    for (const wchar_t* scheme : schemes) {
        size_t pos = 0;
        while (pos < value.size()) {
            size_t found = value.find(scheme, pos);
            if (found == std::wstring::npos) break;
            size_t end = found;
            while (end < value.size()) {
                wchar_t c = value[end];
                if (iswspace(c) || c == L'"' || c == L'\'' || c == L'<' || c == L'>' || c == L'\0') break;
                ++end;
            }
            if (end - found >= wcslen(scheme) + 1) {
                std::wstring url = value.substr(found, end - found);
                while (!url.empty() && (url.back() == L'.' || url.back() == L',' ||
                                        url.back() == L')' || url.back() == L']' || url.back() == L';')) {
                    url.pop_back();
                }
                if (!url.empty()) return url;
            }
            pos = found + 1;
        }
    }
    return L"";
}

} // namespace

bool EtwEventDecoder::FindUrl(std::wstring& url, std::wstring& fieldName) const {
    url.clear();
    fieldName.clear();
    if (!valid_ || !info_) return false;
    for (ULONG i = 0; i < info_->PropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& property = info_->EventPropertyInfoArray[i];
        if (property.Flags & PropertyStruct) continue;
        USHORT inType = property.nonStructType.InType;
        if (inType != 1 && inType != 2) continue;
        if (!property.NameOffset) continue;
        const wchar_t* name = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info_) + property.NameOffset);
        std::vector<BYTE> raw;
        if (!Query(name, raw) || raw.empty()) continue;
        std::wstring text;
        if (inType == 1) {
            size_t chars = raw.size() / sizeof(wchar_t);
            text.assign(reinterpret_cast<const wchar_t*>(raw.data()), chars);
            size_t nullPos = text.find(L'\0');
            if (nullPos != std::wstring::npos) text.resize(nullPos);
        } else {
            text.reserve(raw.size());
            for (BYTE c : raw) {
                if (c == 0) break;
                text.push_back(static_cast<wchar_t>(c));
            }
        }
        if (text.empty()) continue;
        std::wstring found = ExtractUrl(text);
        if (!found.empty()) {
            url = found;
            fieldName = name;
            return true;
        }
    }
    return false;
}
