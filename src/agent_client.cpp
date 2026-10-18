#include "agent_client.h"
#include "util.h"

#include <shellapi.h>
#include <objbase.h>
#include <algorithm>
#include <cstring>

namespace {

std::wstring NewGuidText() {
    GUID guid = {};
    CoCreateGuid(&guid);
    wchar_t buffer[64] = {};
    StringFromGUID2(guid, buffer, 64);
    std::wstring text = buffer;
    text.erase(std::remove_if(text.begin(), text.end(), [](wchar_t c) {
        return c == L'{' || c == L'}' || c == L'-';
    }), text.end());
    return text;
}

bool ReadLineFromPipe(HANDLE pipe, std::string& pending, std::string& line) {
    char buffer[8192];
    for (;;) {
        size_t pos = pending.find('\n');
        if (pos != std::string::npos) {
            line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return true;
        }
        if (pending.size() > 4 * 1024 * 1024) pending.clear();
        DWORD read = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) || read == 0) return false;
        pending.append(buffer, read);
    }
}

bool WriteAllPipe(HANDLE pipe, const std::string& data) {
    size_t offset = 0;
    while (offset < data.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 65536));
        DWORD written = 0;
        if (!WriteFile(pipe, data.data() + offset, chunk, &written, nullptr) || written == 0) return false;
        offset += written;
    }
    return true;
}

std::vector<std::wstring> SplitParts(const std::wstring& text) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (;;) {
        size_t pos = text.find(L'\t', start);
        if (pos == std::wstring::npos) {
            parts.push_back(text.substr(start));
            break;
        }
        parts.push_back(text.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

bool ParseUInt(const std::wstring& text, unsigned& value) {
    if (text.empty()) return false;
    wchar_t* end = nullptr;
    unsigned long v = wcstoul(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != L'\0' || v > 0xFFFFFFFFul) return false;
    value = static_cast<unsigned>(v);
    return true;
}

bool ParseU64(const std::wstring& text, unsigned long long& value) {
    if (text.empty()) return false;
    wchar_t* end = nullptr;
    unsigned long long v = wcstoull(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != L'\0') return false;
    value = v;
    return true;
}

HANDLE CreatePipeServer(const std::wstring& name) {
    return CreateNamedPipeW(
        name.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 1024 * 1024, 1024 * 1024, 0, nullptr);
}

} // namespace

AgentClient::AgentClient() = default;
AgentClient::~AgentClient() {
    Shutdown();
    if (worker_.joinable()) {
        for (int i = 0; i < 100 && !workerDone_.load(); ++i) Sleep(10);
        if (worker_.joinable()) {
            if (workerDone_.load()) worker_.join();
            else worker_.detach();
        }
    }
}

bool AgentClient::Launch(std::wstring& error) {
    if (state_.load() == AgentRunState::Starting) {
        error = L"Служба наблюдения уже запускается.";
        return false;
    }
    if (worker_.joinable()) {
        if (!workerDone_.load()) {
            error = L"Служба наблюдения уже работает.";
            return false;
        }
        worker_.join();
    }
    ClosePipe();
    {
        std::lock_guard<std::mutex> lock(eventsMutex_);
        events_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(infoMutex_);
        error_.clear();
        agentStatus_.clear();
        agentMessage_.clear();
        ++statusSequence_;
    }
    state_ = AgentRunState::Starting;
    shutdown_ = false;
    workerDone_ = false;
    expectedSession_ = 0;

    std::wstring id = NewGuidText();
    std::wstring commandName = L"\\\\.\\pipe\\WatchProg-cmd-" + id;
    std::wstring eventName = L"\\\\.\\pipe\\WatchProg-evt-" + id;
    std::wstring secret = id + id;
    HANDLE commandPipe = CreatePipeServer(commandName);
    HANDLE eventPipe = commandPipe == INVALID_HANDLE_VALUE ? INVALID_HANDLE_VALUE : CreatePipeServer(eventName);
    if (commandPipe == INVALID_HANDLE_VALUE || eventPipe == INVALID_HANDLE_VALUE) {
        if (commandPipe != INVALID_HANDLE_VALUE) CloseHandle(commandPipe);
        if (eventPipe != INVALID_HANDLE_VALUE) CloseHandle(eventPipe);
        error = L"Не удалось создать каналы связи со службой наблюдения: " + FormatWinError(GetLastError());
        SetFailed(error);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(pipeMutex_);
        commandPipe_ = commandPipe;
        eventPipe_ = eventPipe;
    }

    std::wstring exe = GetExePath();
    std::wstring exeDir = GetExeDirectory();
    std::wstring parameters = L"--agent " + QuoteArg(commandName) + L" " + QuoteArg(eventName) + L" " + QuoteArg(secret);
    worker_ = std::thread([this, commandPipe, eventPipe, secret, exe, exeDir, parameters]() {
        SHELLEXECUTEINFOW info = {};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        info.lpVerb = L"runas";
        info.lpFile = exe.c_str();
        info.lpParameters = parameters.c_str();
        info.lpDirectory = exeDir.c_str();
        info.nShow = SW_HIDE;
        BOOL launched = ShellExecuteExW(&info);
        if (!launched) {
            DWORD code = GetLastError();
            std::wstring message;
            if (code == ERROR_CANCELLED) {
                message = L"Запрос прав администратора отменён. Наблюдение за действиями программы невозможно без этих прав.";
            } else {
                message = L"Не удалось запустить службу наблюдения: " + FormatWinError(code);
            }
            SetFailed(message);
            ClosePipe();
            workerDone_ = true;
            return;
        }
        HANDLE agentProcess = info.hProcess;
        BOOL connected = ConnectNamedPipe(commandPipe, nullptr);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            SetFailed(L"Служба наблюдения не подключилась: " + FormatWinError(connectError));
            if (agentProcess) CloseHandle(agentProcess);
            ClosePipe();
            workerDone_ = true;
            return;
        }
        connected = ConnectNamedPipe(eventPipe, nullptr);
        connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            SetFailed(L"Служба наблюдения не подключилась: " + FormatWinError(connectError));
            if (agentProcess) CloseHandle(agentProcess);
            ClosePipe();
            workerDone_ = true;
            return;
        }

        std::string pending;
        std::string helloLine;
        if (!ReadLineFromPipe(eventPipe, pending, helloLine) ||
            Utf8ToWide(helloLine).rfind(L"HELLO\t", 0) != 0) {
            SetFailed(L"Служба наблюдения не прошла проверку подключения.");
            if (agentProcess) CloseHandle(agentProcess);
            ClosePipe();
            workerDone_ = true;
            return;
        }
        std::wstring hello = Utf8ToWide(helloLine);
        std::wstring expectedHello = L"HELLO\t" + secret + L"\t" + std::to_wstring(WATCHPROG_PROTOCOL);
        if (hello != expectedHello) {
            SetFailed(L"Версия службы наблюдения не совпадает. Перезапустите программу.");
            if (agentProcess) CloseHandle(agentProcess);
            ClosePipe();
            workerDone_ = true;
            return;
        }

        state_ = AgentRunState::Ready;
        {
            std::lock_guard<std::mutex> lock(infoMutex_);
            error_.clear();
            agentStatus_ = L"ready";
            agentMessage_ = L"Служба наблюдения запущена.";
            ++statusSequence_;
        }

        std::string rawLine;
        std::wstring line;
        while (!shutdown_.load() && ReadLineFromPipe(eventPipe, pending, rawLine)) {
            line = Utf8ToWide(rawLine);
            auto parts = SplitParts(line);
            if (parts.size() >= 8 && parts[0] == L"EVT") {
                unsigned session = 0;
                if (ParseUInt(parts[1], session) && session == expectedSession_.load()) {
                    unsigned long long timeValue = 0;
                    unsigned category = 0;
                    if (ParseU64(parts[2], timeValue) && ParseUInt(parts[3], category) && category < CatCount) {
                        LogEvent event;
                        event.time = U64ToFileTime(timeValue);
                        event.category = static_cast<int>(category);
                        event.action = UnescapeField(parts[4]);
                        event.object = UnescapeField(parts[5]);
                        event.details = UnescapeField(parts[6]);
                        event.underline = parts[7] == L"1";
                        std::lock_guard<std::mutex> lock(eventsMutex_);
                        if (events_.size() < 200000) events_.push_back(std::move(event));
                        else ++droppedEvents_;
                    }
                }
            } else if (parts.size() >= 3 && parts[0] == L"STATE") {
                unsigned session = 0;
                if (!ParseUInt(parts[1], session)) continue;
                unsigned expected = expectedSession_.load();
                if (session != 0 && expected != 0 && session != expected) continue;
                std::wstring status = parts[2];
                std::wstring message = parts.size() >= 4 ? UnescapeField(parts[3]) : L"";
                {
                    std::lock_guard<std::mutex> lock(infoMutex_);
                    agentStatus_ = status;
                    agentMessage_ = message;
                    if (status == L"error" && !message.empty()) error_ = message;
                    ++statusSequence_;
                }
            }
        }

        if (state_.load() != AgentRunState::Failed) {
            if (state_.load() == AgentRunState::Starting) {
                SetFailed(L"Служба наблюдения завершила работу до подключения.");
            } else {
                state_ = AgentRunState::Disconnected;
                std::lock_guard<std::mutex> lock(infoMutex_);
                error_ = L"Служба наблюдения завершилась.";
                ++statusSequence_;
            }
        }
        if (agentProcess) CloseHandle(agentProcess);
        ClosePipe();
        workerDone_ = true;
    });
    return true;
}

void AgentClient::SetFailed(const std::wstring& error) {
    {
        std::lock_guard<std::mutex> lock(infoMutex_);
        error_ = error;
        ++statusSequence_;
    }
    state_ = AgentRunState::Failed;
}

void AgentClient::ClosePipe() {
    std::lock_guard<std::mutex> lock(pipeMutex_);
    if (commandPipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(commandPipe_);
        commandPipe_ = INVALID_HANDLE_VALUE;
    }
    if (eventPipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(eventPipe_);
        eventPipe_ = INVALID_HANDLE_VALUE;
    }
}

bool AgentClient::WriteLine(const std::wstring& line, std::wstring& error) {
    if (!IsReady()) {
        error = L"Служба наблюдения ещё не готова.";
        return false;
    }
    std::wstring data = line + L"\n";
    std::string utf8 = WideToUtf8(data);
    std::lock_guard<std::mutex> writeLock(writeMutex_);
    std::lock_guard<std::mutex> pipeLock(pipeMutex_);
    if (commandPipe_ == INVALID_HANDLE_VALUE) {
        error = L"Канал связи со службой наблюдения закрыт.";
        return false;
    }
    if (!WriteAllPipe(commandPipe_, utf8)) {
        error = L"Не удалось передать команду службе наблюдения: " + FormatWinError(GetLastError());
        return false;
    }
    return true;
}

bool AgentClient::SendStart(unsigned session, const std::wstring& path, std::wstring& error) {
    {
        std::lock_guard<std::mutex> lock(eventsMutex_);
        events_.clear();
    }
    expectedSession_ = session;
    return WriteLine(L"START\t" + std::to_wstring(session) + L"\t" + EscapeField(path), error);
}

bool AgentClient::SendStop(std::wstring& error) {
    return WriteLine(L"STOP", error);
}

void AgentClient::SetExpectedSession(unsigned session) {
    expectedSession_ = session;
    std::lock_guard<std::mutex> lock(eventsMutex_);
    events_.clear();
}

std::vector<LogEvent> AgentClient::DrainEvents() {
    std::vector<LogEvent> result;
    std::lock_guard<std::mutex> lock(eventsMutex_);
    result.reserve(events_.size());
    while (!events_.empty()) {
        result.emplace_back(std::move(events_.front()));
        events_.pop_front();
    }
    return result;
}

AgentSnapshot AgentClient::Snapshot() const {
    AgentSnapshot snapshot;
    snapshot.state = state_.load();
    snapshot.dropped = droppedEvents_.load();
    std::lock_guard<std::mutex> lock(infoMutex_);
    snapshot.error = error_;
    snapshot.status = agentStatus_;
    snapshot.message = agentMessage_;
    snapshot.statusSequence = statusSequence_;
    return snapshot;
}

void AgentClient::Shutdown() {
    if (shutdown_.exchange(true)) {
        ClosePipe();
        return;
    }
    if (IsReady()) {
        std::wstring ignored;
        WriteLine(L"QUIT", ignored);
    }
    ClosePipe();
}
