#ifndef WATCHPROG_ETW_H
#define WATCHPROG_ETW_H

#include "app.h"
#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>

using EtwCallback = void (*)(PEVENT_RECORD event);

class EtwSession {
public:
    EtwSession() = default;
    ~EtwSession();
    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    bool Start(const std::wstring& sessionName, bool systemLogger, std::wstring& error);
    bool EnableProvider(const GUID& provider, UCHAR level, ULONGLONG anyKeyword,
                        ULONGLONG allKeyword, std::wstring& error);
    bool BeginConsume(EtwCallback callback, void* context, std::wstring& error);
    void Stop();
    bool IsActive() const { return active_; }
    const std::wstring& Error() const { return error_; }

private:
    TRACEHANDLE traceHandle_ = 0;
    TRACEHANDLE consumerHandle_ = 0;
    std::vector<BYTE> properties_;
    std::wstring sessionName_;
    std::wstring error_;
    std::thread consumerThread_;
    std::atomic<bool> active_{false};
    std::atomic<bool> consumeDone_{false};
};

// Decodes one ETW event by property name. Only valid inside the event callback.
class EtwEventDecoder {
public:
    explicit EtwEventDecoder(PEVENT_RECORD event);
    bool IsValid() const { return valid_; }
    ULONG Status() const { return status_; }

    bool GetString(const wchar_t* name, std::wstring& value) const;
    bool GetUInt32(const wchar_t* name, DWORD& value) const;
    bool GetUInt64(const wchar_t* name, ULONGLONG& value) const;
    bool GetBinary(const wchar_t* name, std::vector<BYTE>& value) const;
    bool HasProperty(const wchar_t* name) const;
    bool FindUrl(std::wstring& url, std::wstring& fieldName) const;

private:
    bool Query(const wchar_t* name, std::vector<BYTE>& value) const;
    PEVENT_RECORD event_ = nullptr;
    PTRACE_EVENT_INFO info_ = nullptr;
    bool valid_ = false;
    ULONG status_ = ERROR_SUCCESS;
};

#endif
