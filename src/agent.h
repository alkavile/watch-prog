#ifndef WATCHPROG_AGENT_H
#define WATCHPROG_AGENT_H

#include "app.h"

int AgentMain(const std::wstring& commandPipeName, const std::wstring& eventPipeName,
              const std::wstring& secret);

#endif
