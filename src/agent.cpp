#include "agent.h"
#include "launcher.h"
#include "monitor.h"
#include "util.h"

#include <evntrace.h>
#include <atomic>
#include <algorithm>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

bool WriteAll(HANDLE pipe, const std::string& data) {
    size_t offset = 0;
    while (offset < data.size()) {
        DWORD written = 0;
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 65536));
        if (!WriteFile(pipe, data.data() + offset, chunk, &written, nullptr) || written == 0) return false;
        offset += written;
    }
    return true;
}

bool SendLine(HANDLE pipe, const std::wstring& line) {
    std::wstring text = line;
    text += L"\n";
    return WriteAll(pipe, WideToUtf8(text));
}

std::wstring MakeState(unsigned session, const wchar_t* state, const std::wstring& message) {
    return L"STATE\t" + std::to_wstring(session) + L"\t" + state + L"\t" + EscapeField(message);
}

std::wstring MakeEvent(unsigned session, const LogEvent& event) {
    return L"EVT\t" + std::to_wstring(session) + L"\t" +
           std::to_wstring(FileTimeToU64(event.time)) + L"\t" +
           std::to_wstring(event.category) + L"\t" +
           EscapeField(event.action) + L"\t" +
           EscapeField(event.object) + L"\t" +
           EscapeField(event.details) + L"\t" +
           (event.underline ? L"1" : L"0");
}

bool ParseSession(const std::wstring& text, unsigned& session) {
    wchar_t* end = nullptr;
    unsigned long value = wcstoul(text.c_str(), &end, 10);
    if (end == text.c_str() || value > 0xFFFFFFFFul) return false;
    session = static_cast<unsigned>(value);
    return true;
}

std::vector<std::wstring> SplitTabs(const std::wstring& line) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (;;) {
        size_t pos = line.find(L'\t', start);
        if (pos == std::wstring::npos) {
            parts.push_back(line.substr(start));
            break;
        }
        parts.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

void CleanupStaleSessions() {
    ULONG count = 0;
    ULONG status = QueryAllTracesW(nullptr, 0, &count);
    if ((status != ERROR_SUCCESS && status != ERROR_MORE_DATA && status != ERROR_INSUFFICIENT_BUFFER) ||
        count == 0) {
        return;
    }
    if (count > 256) count = 256;
    const ULONG capacity = count;
    const ULONG bufferSize = 2048;
    std::vector<std::vector<BYTE>> buffers(capacity);
    std::vector<PEVENT_TRACE_PROPERTIES> properties(capacity, nullptr);
    for (ULONG i = 0; i < capacity; ++i) {
        buffers[i].assign(bufferSize, 0);
        properties[i] = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffers[i].data());
        properties[i]->Wnode.BufferSize = bufferSize;
    }
    status = QueryAllTracesW(properties.data(), capacity, &count);
    if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA && status != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }
    if (count > capacity) count = capacity;
    for (ULONG i = 0; i < count; ++i) {
        auto* props = properties[i];
        if (!props || !props->LoggerNameOffset) continue;
        const wchar_t* name = reinterpret_cast<const wchar_t*>(buffers[i].data() + props->LoggerNameOffset);
        const wchar_t* rest = nullptr;
        if (wcsncmp(name, L"WatchProg-Kernel-", 17) == 0) rest = name + 17;
        else if (wcsncmp(name, L"WatchProg-User-", 15) == 0) rest = name + 15;
        if (!rest) continue;
        wchar_t* end = nullptr;
        DWORD pid = wcstoul(rest, &end, 10);
        if (end == rest) continue;
        std::wstring image = pid ? GetProcessPath(pid) : L"";
        bool live = !image.empty() && EndsWithI(image, L"WatchProg.exe");
        if (live) continue;
        ControlTraceW(0, name, props, EVENT_TRACE_CONTROL_STOP);
    }
}

HANDLE ConnectPipeClient(const std::wstring& name) {
    for (int attempt = 0; attempt < 40; ++attempt) {
        HANDLE pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                  OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) return pipe;
        Sleep(50);
    }
    return INVALID_HANDLE_VALUE;
}

struct AgentContext {
    HANDLE commandPipe = INVALID_HANDLE_VALUE;
    HANDLE eventPipe = INVALID_HANDLE_VALUE;
    HANDLE commandEvent = nullptr;
    std::thread reader;
    std::mutex commandMutex;
    std::deque<std::wstring> commands;
    std::atomic<bool> quit{ false };
    std::atomic<bool> pipeBroken{ false };
};

void ReaderThread(AgentContext* ctx) {
    std::string pending;
    char buffer[8192];
    for (;;) {
        DWORD read = 0;
        BOOL ok = ReadFile(ctx->commandPipe, buffer, sizeof(buffer), &read, nullptr);
        if (!ok || read == 0) break;
        pending.append(buffer, read);
        if (pending.size() > 1024 * 1024) pending.clear();
        for (;;) {
            size_t pos = pending.find('\n');
            if (pos == std::string::npos) break;
            std::string raw = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!raw.empty() && raw.back() == '\r') raw.pop_back();
            {
                std::lock_guard<std::mutex> lock(ctx->commandMutex);
                ctx->commands.push_back(Utf8ToWide(raw));
            }
            SetEvent(ctx->commandEvent);
        }
    }
    ctx->quit = true;
    SetEvent(ctx->commandEvent);
}

} // namespace

int AgentMain(const std::wstring& commandPipeName, const std::wstring& eventPipeName,
              const std::wstring& secret) {
    HANDLE commandPipe = ConnectPipeClient(commandPipeName);
    if (commandPipe == INVALID_HANDLE_VALUE) return 10;
    HANDLE eventPipe = ConnectPipeClient(eventPipeName);
    if (eventPipe == INVALID_HANDLE_VALUE) {
        CloseHandle(commandPipe);
        return 11;
    }

    HANDLE commandEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!commandEvent) {
        CloseHandle(eventPipe);
        CloseHandle(commandPipe);
        return 12;
    }

    AgentContext context;
    context.commandPipe = commandPipe;
    context.eventPipe = eventPipe;
    context.commandEvent = commandEvent;

    if (!SendLine(eventPipe, L"HELLO\t" + secret + L"\t" + std::to_wstring(WATCHPROG_PROTOCOL))) {
        CloseHandle(commandEvent);
        CloseHandle(eventPipe);
        CloseHandle(commandPipe);
        return 13;
    }

    if (!IsProcessElevated()) {
        SendLine(eventPipe, MakeState(0, L"error", L"Служба наблюдения не получила права администратора."));
        CloseHandle(commandEvent);
        CloseHandle(eventPipe);
        CloseHandle(commandPipe);
        return 14;
    }

    CleanupStaleSessions();
    context.reader = std::thread(ReaderThread, &context);
    Monitor monitor;
    unsigned currentSession = 0;
    bool running = false;
    bool targetWasRunning = false;
    ULONGLONG autoStopAt = 0;

    SendLine(eventPipe, MakeState(0, L"ready", L"Служба наблюдения запущена."));

    while (!context.quit.load()) {
        WaitForSingleObject(commandEvent, 50);
        std::deque<std::wstring> commands;
        {
            std::lock_guard<std::mutex> lock(context.commandMutex);
            commands.swap(context.commands);
        }
        for (const auto& line : commands) {
            if (line == L"QUIT") {
                context.quit = true;
                break;
            }
            if (line == L"STOP") {
                if (running) {
                    monitor.Stop();
                    for (const auto& event : monitor.DrainEvents()) {
                        if (!SendLine(eventPipe, MakeEvent(currentSession, event))) context.pipeBroken = true;
                    }
                    running = false;
                    targetWasRunning = false;
                    autoStopAt = 0;
                    SendLine(eventPipe, MakeState(currentSession, L"stopped", L"Наблюдение остановлено."));
                } else {
                    SendLine(eventPipe, MakeState(currentSession, L"stopped", L"Наблюдение уже остановлено."));
                }
                continue;
            }
            auto parts = SplitTabs(line);
            if (parts.size() >= 3 && parts[0] == L"START") {
                unsigned session = 0;
                if (!ParseSession(parts[1], session)) continue;
                std::wstring path = UnescapeField(parts[2]);
                if (running) {
                    monitor.Stop();
                    monitor.DrainEvents();
                    running = false;
                    targetWasRunning = false;
                }
                autoStopAt = 0;
                CleanupStaleSessions();
                std::wstring extension = ExtensionOf(path);
                std::wstring error;
                if (!FileExists(path) || IsDirectory(path)) {
                    SendLine(eventPipe, MakeState(session, L"error", L"Файл не найден: " + path));
                    continue;
                }
                if (!IsSupportedExtension(extension)) {
                    SendLine(eventPipe, MakeState(session, L"error", L"Формат файла не поддерживается."));
                    continue;
                }
                currentSession = session;
                if (!monitor.Start(path, extension, error)) {
                    SendLine(eventPipe, MakeState(session, L"error", error));
                    running = false;
                    continue;
                }
                PreparedTarget target;
                if (!Launcher_Prepare(path, extension, target, error)) {
                    monitor.Stop();
                    SendLine(eventPipe, MakeState(session, L"error", error));
                    running = false;
                    continue;
                }
                monitor.AttachRoot(target.pid);
                if (!Launcher_Resume(target, error)) {
                    Launcher_Close(target);
                    monitor.Stop();
                    SendLine(eventPipe, MakeState(session, L"error", error));
                    running = false;
                    continue;
                }
                Launcher_Close(target);
                running = true;
                targetWasRunning = true;
                SendLine(eventPipe, MakeState(session, L"started", L"Наблюдение начато."));
                continue;
            }
            if (!parts.empty() && parts[0] == L"PING") {
                SendLine(eventPipe, MakeState(currentSession, L"pong", L""));
            }
        }

        if (running) {
            auto events = monitor.DrainEvents();
            for (const auto& event : events) {
                if (!SendLine(eventPipe, MakeEvent(currentSession, event))) {
                    context.pipeBroken = true;
                    break;
                }
            }
            if (!context.pipeBroken) {
                if (targetWasRunning && !monitor.TargetRunning()) {
                    targetWasRunning = false;
                    autoStopAt = GetTickCount64() + 2500;
                }
                if (!targetWasRunning && autoStopAt != 0) {
                    if (monitor.TargetRunning()) {
                        targetWasRunning = true;
                        autoStopAt = 0;
                    } else if (GetTickCount64() >= autoStopAt) {
                        monitor.Stop();
                        for (const auto& event : monitor.DrainEvents()) {
                            if (!SendLine(eventPipe, MakeEvent(currentSession, event))) {
                                context.pipeBroken = true;
                                break;
                            }
                        }
                        running = false;
                        autoStopAt = 0;
                        if (!context.pipeBroken) {
                            SendLine(eventPipe, MakeState(currentSession, L"completed",
                                L"Все процессы завершены. Наблюдение остановлено автоматически."));
                        }
                    }
                }
            }
        }
        if (context.pipeBroken.load()) break;
    }

    monitor.Stop();
    if (!context.pipeBroken.load()) {
        SendLine(eventPipe, MakeState(currentSession, L"stopped", L"Служба наблюдения завершает работу."));
    }
    context.quit = true;
    CloseHandle(eventPipe);
    CloseHandle(commandPipe);
    if (context.reader.joinable()) context.reader.join();
    CloseHandle(commandEvent);
    return 0;
}
