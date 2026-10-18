#ifndef WATCHPROG_MONITOR_H
#define WATCHPROG_MONITOR_H

#include "app.h"
#include <memory>

class Monitor {
public:
    Monitor();
    ~Monitor();
    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;

    bool Start(const std::wstring& targetPath, const std::wstring& extension, std::wstring& error);
    void AttachRoot(DWORD pid);
    void Stop();
    bool Active() const;
    bool TargetRunning() const;
    DWORD RootPid() const;
    std::vector<LogEvent> DrainEvents();
    unsigned long long DroppedCount() const;
    std::wstring StatusText() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif
