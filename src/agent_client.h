#ifndef WATCHPROG_AGENT_CLIENT_H
#define WATCHPROG_AGENT_CLIENT_H

#include "app.h"
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class AgentRunState {
    NotStarted = 0,
    Starting,
    Ready,
    Failed,
    Disconnected
};

struct AgentSnapshot {
    AgentRunState state = AgentRunState::NotStarted;
    std::wstring error;
    std::wstring status;
    std::wstring message;
    unsigned statusSequence = 0;
    unsigned long long dropped = 0;
};

class AgentClient {
public:
    AgentClient();
    ~AgentClient();

    bool Launch(std::wstring& error);
    void Shutdown();
    AgentSnapshot Snapshot() const;
    bool SendStart(unsigned session, const std::wstring& path, std::wstring& error);
    bool SendStop(std::wstring& error);
    void SetExpectedSession(unsigned session);
    std::vector<LogEvent> DrainEvents();

private:
    void SetFailed(const std::wstring& error);
    void ClosePipe();
    bool WriteLine(const std::wstring& line, std::wstring& error);
    bool IsReady() const { return state_.load() == AgentRunState::Ready; }

    std::atomic<AgentRunState> state_{ AgentRunState::NotStarted };
    mutable std::mutex infoMutex_;
    std::wstring error_;
    std::wstring agentStatus_;
    std::wstring agentMessage_;
    unsigned statusSequence_ = 0;

    std::mutex eventsMutex_;
    std::deque<LogEvent> events_;
    std::atomic<unsigned long long> droppedEvents_{ 0 };

    std::mutex pipeMutex_;
    HANDLE commandPipe_ = INVALID_HANDLE_VALUE;
    HANDLE eventPipe_ = INVALID_HANDLE_VALUE;
    std::mutex writeMutex_;
    std::atomic<unsigned> expectedSession_{ 0 };
    std::atomic<bool> shutdown_{ false };

    std::thread worker_;
    std::atomic<bool> workerDone_{ false };
};

#endif
