#include "report.h"
#include "util.h"

#include <commdlg.h>
#include <algorithm>
#include <string>
#include <vector>

namespace {

std::wstring SanitizeLine(std::wstring text) {
    for (wchar_t& c : text) {
        if (c == L'\r' || c == L'\n' || c == L'\t') c = L' ';
    }
    return text;
}

std::wstring JsonEscape(const std::wstring& text) {
    std::wstring result;
    result.reserve(text.size() + 8);
    wchar_t buffer[8] = {};
    for (wchar_t c : text) {
        switch (c) {
            case L'\\': result += L"\\\\"; break;
            case L'"': result += L"\\\""; break;
            case L'\n': result += L"\\n"; break;
            case L'\r': result += L"\\r"; break;
            case L'\t': result += L"\\t"; break;
            default:
                if (c < 0x20) {
                    swprintf(buffer, 8, L"\\u%04x", static_cast<unsigned>(c));
                    result += buffer;
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

std::wstring XmlEscape(const std::wstring& text, bool attribute = false) {
    std::wstring result;
    result.reserve(text.size() + 8);
    for (wchar_t c : text) {
        switch (c) {
            case L'&': result += L"&amp;"; break;
            case L'<': result += L"&lt;"; break;
            case L'>': result += L"&gt;"; break;
            case L'"': result += attribute ? L"&quot;" : L"\""; break;
            case L'\'': result += attribute ? L"&apos;" : L"'"; break;
            case L'\r':
            case L'\n':
            case L'\t':
                result += attribute ? L' ' : c;
                break;
            default: result += c; break;
        }
    }
    return result;
}

std::wstring IniQuote(const std::wstring& text) {
    std::wstring result = L"\"";
    for (wchar_t c : text) {
        switch (c) {
            case L'\\': result += L"\\\\"; break;
            case L'"': result += L"\\\""; break;
            case L'\r': result += L"\\r"; break;
            case L'\n': result += L"\\n"; break;
            case L'\t': result += L"\\t"; break;
            default: result += c; break;
        }
    }
    result += L"\"";
    return result;
}

std::wstring SuggestedName() {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t name[96] = {};
    swprintf(name, 96, L"WatchProg-%04u%02u%02u-%02u%02u%02u.log",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return name;
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& content, bool bom) {
    std::string utf8;
    if (bom) utf8 += "\xEF\xBB\xBF";
    utf8 += WideToUtf8(content);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    size_t offset = 0;
    bool ok = true;
    while (offset < utf8.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(utf8.size() - offset, 1 << 20));
        DWORD written = 0;
        if (!WriteFile(file, utf8.data() + offset, chunk, &written, nullptr) || written == 0) {
            ok = false;
            break;
        }
        offset += written;
    }
    CloseHandle(file);
    return ok;
}

std::wstring BuildLog(const std::vector<LogEvent>& events, const std::wstring& targetPath) {
    std::wstring out;
    out += WATCHPROG_VERSION_FULL;
    out += L"\r\n";
    if (!targetPath.empty()) out += L"Объект: " + targetPath + L"\r\n";
    out += L"Экспорт: " + FormatDateTime(NowFileTime(), false) + L"\r\n";
    out += L"Событий: " + std::to_wstring(events.size()) + L"\r\n";
    out += L"================================================================================\r\n";
    for (const auto& event : events) {
        out += L"[" + FormatDateTime(event.time, false) + L"] [" + CategoryName(event.category) + L"] ";
        out += SanitizeLine(event.action);
        if (!event.object.empty()) out += L" | " + SanitizeLine(event.object);
        if (!event.details.empty()) out += L" | " + SanitizeLine(event.details);
        if (event.underline) out += L" | ОСНОВНОЙ ФАЙЛ ЗАКРЫТ";
        out += L"\r\n";
    }
    return out;
}

std::wstring BuildXml(const std::vector<LogEvent>& events, const std::wstring& targetPath) {
    std::wstring out = L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
    out += L"<watchprog version=\"" + XmlEscape(WATCHPROG_VERSION, true) + L"\"";
    out += L" target=\"" + XmlEscape(targetPath, true) + L"\">\r\n";
    out += L"  <events count=\"" + std::to_wstring(events.size()) + L"\">\r\n";
    for (const auto& event : events) {
        out += L"    <event time=\"" + XmlEscape(FormatDateTime(event.time, false), true) +
               L"\" category=\"" + XmlEscape(CategoryName(event.category), true) +
               L"\" action=\"" + XmlEscape(event.action, true) +
               L"\" object=\"" + XmlEscape(event.object, true) +
               L"\" details=\"" + XmlEscape(event.details, true) +
               L"\" underlined=\"" + (event.underline ? L"true" : L"false") + L"\"/>\r\n";
    }
    out += L"  </events>\r\n</watchprog>\r\n";
    return out;
}

std::wstring BuildJson(const std::vector<LogEvent>& events, const std::wstring& targetPath) {
    std::wstring out = L"{\r\n";
    out += L"  \"program\": \"" WATCHPROG_NAME L"\",\r\n";
    out += L"  \"version\": \"" WATCHPROG_VERSION L"\",\r\n";
    out += L"  \"target\": \"" + JsonEscape(targetPath) + L"\",\r\n";
    out += L"  \"exported_at\": \"" + JsonEscape(FormatDateTime(NowFileTime(), false)) + L"\",\r\n";
    out += L"  \"events\": [\r\n";
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        out += L"    {\r\n";
        out += L"      \"time\": \"" + JsonEscape(FormatDateTime(event.time, false)) + L"\",\r\n";
        out += L"      \"category\": \"" + JsonEscape(CategoryName(event.category)) + L"\",\r\n";
        out += L"      \"action\": \"" + JsonEscape(event.action) + L"\",\r\n";
        out += L"      \"object\": \"" + JsonEscape(event.object) + L"\",\r\n";
        out += L"      \"details\": \"" + JsonEscape(event.details) + L"\",\r\n";
        out += L"      \"underlined\": " + std::wstring(event.underline ? L"true" : L"false") + L"\r\n";
        out += L"    }";
        if (i + 1 < events.size()) out += L",";
        out += L"\r\n";
    }
    out += L"  ]\r\n}\r\n";
    return out;
}

std::wstring BuildIni(const std::vector<LogEvent>& events, const std::wstring& targetPath) {
    std::wstring out;
    out += L"[WatchProg]\r\n";
    out += L"Version=" + IniQuote(WATCHPROG_VERSION) + L"\r\n";
    out += L"Target=" + IniQuote(targetPath) + L"\r\n";
    out += L"Exported=" + IniQuote(FormatDateTime(NowFileTime(), false)) + L"\r\n";
    out += L"Events=" + std::to_wstring(events.size()) + L"\r\n\r\n";
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        out += L"[Event" + std::to_wstring(i + 1) + L"]\r\n";
        out += L"Time=" + IniQuote(FormatDateTime(event.time, false)) + L"\r\n";
        out += L"Category=" + IniQuote(CategoryName(event.category)) + L"\r\n";
        out += L"Action=" + IniQuote(event.action) + L"\r\n";
        out += L"Object=" + IniQuote(event.object) + L"\r\n";
        out += L"Details=" + IniQuote(event.details) + L"\r\n";
        out += L"Underlined=" + std::wstring(event.underline ? L"true" : L"false") + L"\r\n\r\n";
    }
    return out;
}

} // namespace

bool Report_Save(HWND owner, const std::vector<LogEvent>& events, const std::wstring& targetPath) {
    wchar_t path[MAX_PATH] = {};
    std::wstring suggested = SuggestedName();
    wcsncpy(path, suggested.c_str(), MAX_PATH - 1);
    path[MAX_PATH - 1] = L'\0';
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFilter =
        L"Журнал (*.log)\0*.log\0"
        L"XML-журнал (*.xml)\0*.xml\0"
        L"JSON-журнал (*.json)\0*.json\0"
        L"INI-журнал (*.ini)\0*.ini\0";
    dialog.nFilterIndex = 1;
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = L"log";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    dialog.lpstrTitle = L"Сохранить журнал WatchProg";
    if (!GetSaveFileNameW(&dialog)) return false;

    std::wstring outputPath = path;
    std::wstring ext = ExtensionOf(outputPath);
    std::wstring chosenExt;
    switch (dialog.nFilterIndex) {
        case 2: chosenExt = L".xml"; break;
        case 3: chosenExt = L".json"; break;
        case 4: chosenExt = L".ini"; break;
        default: chosenExt = L".log"; break;
    }
    if (ext != L".log" && ext != L".xml" && ext != L".json" && ext != L".ini") {
        outputPath += chosenExt;
        ext = chosenExt;
    }

    std::wstring content;
    bool bom = false;
    if (ext == L".xml") {
        content = BuildXml(events, targetPath);
    } else if (ext == L".json") {
        content = BuildJson(events, targetPath);
    } else if (ext == L".ini") {
        content = BuildIni(events, targetPath);
        bom = true;
    } else {
        content = BuildLog(events, targetPath);
        bom = true;
    }
    if (!WriteUtf8File(outputPath, content, bom)) {
        MessageBoxW(owner, (L"Не удалось сохранить файл: " + FormatWinError(GetLastError())).c_str(),
                    L"WatchProg", MB_OK | MB_ICONERROR);
        return false;
    }
    return true;
}
