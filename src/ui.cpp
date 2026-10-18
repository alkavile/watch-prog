#include "ui.h"
#include "agent_client.h"
#include "report.h"
#include "theme.h"
#include "util.h"

#include <commdlg.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <uxtheme.h>
#include <cwctype>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr UINT_PTR kPollTimer = 1;
constexpr UINT WM_INITIAL_FILE = WM_APP + 12;
constexpr size_t kEventsPerTick = 2500;
constexpr size_t kMaxUiEvents = 250000;

std::wstring UpperExtension(const std::wstring& ext) {
    std::wstring value = ext;
    if (!value.empty() && value[0] == L'.') value.erase(value.begin());
    for (wchar_t& c : value) c = static_cast<wchar_t>(towupper(c));
    return value;
}

std::wstring FirstLine(const std::wstring& text) {
    size_t pos = text.find_first_of(L"\r\n");
    return pos == std::wstring::npos ? text : text.substr(0, pos);
}

void SetIfTextDiffers(HWND control, const std::wstring& text) {
    if (!control) return;
    wchar_t current[1024] = {};
    GetWindowTextW(control, current, 1024);
    if (text == current) return;
    SetWindowTextW(control, text.c_str());
}

void ShowInfo(HWND owner, const std::wstring& text, UINT icon = MB_ICONINFORMATION) {
    MessageBoxW(owner, text.c_str(), L"WatchProg", MB_OK | icon);
}

std::wstring FullPath(const std::wstring& path) {
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return path;
    std::vector<wchar_t> buffer(needed + 1);
    DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) return path;
    return std::wstring(buffer.data(), written);
}

} // namespace

class AppWindow {
public:
    AppWindow(HINSTANCE instance, std::wstring initialFile)
        : instance_(instance), agent_(new AgentClient()), initialFile_(std::move(initialFile)) {
        categoryCounts_.fill(0);
    }

    ~AppWindow() {
        if (agent_) {
            agent_->Shutdown();
            // The agent object intentionally lives until process exit. Its worker may still be
            // blocked in a UAC prompt, and deleting it here could race with that thread.
        }
    }

    int Run(int showCommand) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = instance_;
        wc.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(101));
        if (!wc.hIcon) wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        wc.hIconSm = wc.hIcon;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr;
        wc.lpszClassName = L"WatchProgMainWindow";
        RegisterClassExW(&wc);

        dpi_ = static_cast<int>(GetDpiForSystem());
        if (dpi_ < 72) dpi_ = 96;
        int width = MulDiv(WATCHPROG_WINDOW_W, dpi_, 96);
        int height = MulDiv(WATCHPROG_WINDOW_H, dpi_, 96);
        RECT work = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        int x = work.left + ((work.right - work.left) - width) / 2;
        int y = work.top + ((work.bottom - work.top) - height) / 2;
        if (x < work.left) x = work.left;
        if (y < work.top) y = work.top;

        DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        hwnd_ = CreateWindowExW(
            WS_EX_ACCEPTFILES,
            L"WatchProgMainWindow",
            L"WatchProg — наблюдение за действиями программы",
            style, x, y, width, height,
            nullptr, nullptr, instance_, this);
        if (!hwnd_) return 1;

        ShowWindow(hwnd_, showCommand == 0 ? SW_SHOW : showCommand);
        UpdateWindow(hwnd_);

        ACCEL accelerators[] = {
            { FCONTROL | FVIRTKEY, 'O', IDM_FILE_OPEN },
            { FCONTROL | FVIRTKEY, 'L', IDM_FILE_CLEAR },
            { FCONTROL | FVIRTKEY, 'S', IDM_FILE_EXPORT },
            { FVIRTKEY, VK_F5, IDM_FILE_RERUN },
            { FVIRTKEY, VK_ESCAPE, IDM_FILE_STOP },
        };
        HACCEL accel = CreateAcceleratorTableW(accelerators, 5);

        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            if (accel && TranslateAcceleratorW(hwnd_, accel, &message)) continue;
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (accel) DestroyAcceleratorTable(accel);
        Theme_Shutdown();
        return static_cast<int>(message.wParam);
    }

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
        AppWindow* self = reinterpret_cast<AppWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            self = reinterpret_cast<AppWindow*>(create->lpCreateParams);
            self->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(hwnd, message, wParam, lParam);
        return self->HandleMessage(message, wParam, lParam);
    }

    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
            case WM_CREATE:
                return OnCreate() ? 0 : -1;
            case WM_SIZE:
                Layout();
                return 0;
            case WM_GETMINMAXINFO: {
                auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
                int w = MulDiv(WATCHPROG_WINDOW_W, dpi_, 96);
                int h = MulDiv(WATCHPROG_WINDOW_H, dpi_, 96);
                info->ptMinTrackSize.x = w;
                info->ptMinTrackSize.y = h;
                info->ptMaxTrackSize.x = w;
                info->ptMaxTrackSize.y = h;
                return 0;
            }
            case WM_ERASEBKGND: {
                HDC dc = reinterpret_cast<HDC>(wParam);
                RECT rc;
                GetClientRect(hwnd_, &rc);
                FillRect(dc, &rc, g_theme.windowBrush);
                return 1;
            }
            case WM_PAINT:
                OnPaint();
                return 0;
            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLORBTN: {
                HDC dc = reinterpret_cast<HDC>(wParam);
                HWND control = reinterpret_cast<HWND>(lParam);
                int id = GetDlgCtrlID(control);
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, (id == IDC_VERSION_LABEL || id == IDC_FOOTER_COUNTS) ? g_theme.muted : g_theme.text);
                SetBkColor(dc, g_theme.windowBg);
                return reinterpret_cast<LRESULT>(g_theme.windowBrush);
            }
            case WM_SETTINGCHANGE:
                if (!lParam || _wcsicmp(reinterpret_cast<LPCWSTR>(lParam), L"ImmersiveColorSet") == 0 ||
                    _wcsicmp(reinterpret_cast<LPCWSTR>(lParam), L"WindowMetrics") == 0 ||
                    _wcsicmp(reinterpret_cast<LPCWSTR>(lParam), L"General") == 0) {
                    Theme_Refresh(hwnd_);
                    ApplyFonts();
                    ApplyButtonMode();
                    ApplyColors();
                    Layout();
                    InvalidateRect(hwnd_, nullptr, TRUE);
                }
                return 0;
            case WM_DPICHANGED: {
                dpi_ = HIWORD(wParam);
                RECT* suggested = reinterpret_cast<RECT*>(lParam);
                int width = MulDiv(WATCHPROG_WINDOW_W, dpi_, 96);
                int height = MulDiv(WATCHPROG_WINDOW_H, dpi_, 96);
                SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top, width, height,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                Theme_Refresh(hwnd_);
                ApplyFonts();
                ApplyButtonMode();
                ApplyColors();
                Layout();
                InvalidateRect(hwnd_, nullptr, TRUE);
                return 0;
            }
            case WM_DRAWITEM:
                DrawButton(reinterpret_cast<DRAWITEMSTRUCT*>(lParam));
                return TRUE;
            case WM_COMMAND:
                OnCommand(LOWORD(wParam), HIWORD(wParam));
                return 0;
            case WM_TIMER:
                if (wParam == kPollTimer) PollAgent();
                return 0;
            case WM_DROPFILES:
                OnDrop(reinterpret_cast<HDROP>(wParam));
                return 0;
            case WM_NOTIFY:
                return OnNotify(reinterpret_cast<NMHDR*>(lParam));
            case WM_CLOSE:
                OnClose();
                return 0;
            case WM_DESTROY:
                KillTimer(hwnd_, kPollTimer);
                PostQuitMessage(0);
                return 0;
            case WM_SYSCOMMAND:
                if ((wParam & 0xFFF0) == SC_MAXIMIZE) return 0;
                break;
            case WM_NCLBUTTONDBLCLK:
                if (wParam == HTCAPTION) return 0;
                break;
            case WM_INITIAL_FILE:
                if (!initialFile_.empty()) {
                    std::wstring file = initialFile_;
                    initialFile_.clear();
                    StartFile(file);
                }
                return 0;
            case WM_APP + 13:
                UpdateInterface();
                return 0;
            default:
                break;
        }
        return DefWindowProcW(hwnd_, message, wParam, lParam);
    }

    bool OnCreate() {
        BuildMenu();
        CreateControls();
        DragAcceptFiles(hwnd_, TRUE);
        ChangeWindowMessageFilterEx(hwnd_, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(hwnd_, 0x0049 /* WM_COPYGLOBALDATA */, MSGFLT_ALLOW, nullptr);
        Theme_Initialize(hwnd_);
        ApplyFonts();
        ApplyButtonMode();
        ApplyColors();
        Layout();
        SetFocus(btnOpen_);
        SetStatus(L"Готово. Перетащите файл в окно или нажмите «Открыть файл…».");
        UpdateInterface();
        SetTimer(hwnd_, kPollTimer, 100, nullptr);
        if (!initialFile_.empty()) PostMessageW(hwnd_, WM_INITIAL_FILE, 0, 0);
        return true;
    }

    void BuildMenu() {
        menu_ = CreateMenu();
        HMENU file = CreatePopupMenu();
        HMENU view = CreatePopupMenu();
        HMENU help = CreatePopupMenu();
        AppendMenuW(file, MF_STRING, IDM_FILE_OPEN, L"&Открыть файл…\tCtrl+O");
        AppendMenuW(file, MF_STRING, IDM_FILE_RERUN, L"Запустить &снова\tF5");
        AppendMenuW(file, MF_STRING, IDM_FILE_STOP, L"Оста&новить наблюдение\tEsc");
        AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(file, MF_STRING, IDM_FILE_CLEAR, L"О&чистить журнал\tCtrl+L");
        AppendMenuW(file, MF_STRING, IDM_FILE_EXPORT, L"&Сохранить журнал…\tCtrl+S");
        AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(file, MF_STRING, IDM_FILE_EXIT, L"В&ыход\tAlt+F4");
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_FILES, L"&Файлы и папки");
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_REGISTRY, L"&Реестр");
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_TASKS, L"&Планировщик задач");
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_PROCESSES, L"&Процессы");
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_NETWORK, L"&Сеть и DNS");
        AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(view, MF_STRING | MF_CHECKED, IDM_VIEW_AUTOSCROLL, L"&Автопрокрутка");
        AppendMenuW(help, MF_STRING, IDM_HELP_HOW, L"&Как это работает");
        AppendMenuW(help, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(help, MF_STRING, IDM_HELP_ABOUT, L"&О программе");
        AppendMenuW(menu_, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"&Файл");
        AppendMenuW(menu_, MF_POPUP, reinterpret_cast<UINT_PTR>(view), L"&Вид");
        AppendMenuW(menu_, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"С&правка");
        SetMenu(hwnd_, menu_);
        DrawMenuBar(hwnd_);
    }

    void CreateControls() {
        btnOpen_ = CreateWindowExW(0, L"BUTTON", L"Открыть файл…",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_OPEN_BUTTON), instance_, nullptr);
        btnRerun_ = CreateWindowExW(0, L"BUTTON", L"Запустить снова",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_RERUN_BUTTON), instance_, nullptr);
        btnStop_ = CreateWindowExW(0, L"BUTTON", L"Остановить",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_STOP_BUTTON), instance_, nullptr);
        EnableWindow(btnStop_, FALSE);
        EnableWindow(btnRerun_, FALSE);

        list_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
            LVS_SHOWSELALWAYS | LVS_NOSORTHEADER | LVS_OWNERDATA,
            0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(IDC_LIST), instance_, nullptr);
        ListView_SetExtendedListViewStyle(list_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        LVCOLUMNW column = {};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.cx = 80;
        column.pszText = const_cast<LPWSTR>(L"Время");
        ListView_InsertColumn(list_, 0, &column);
        column.cx = 105;
        column.pszText = const_cast<LPWSTR>(L"Категория");
        ListView_InsertColumn(list_, 1, &column);
        column.cx = 185;
        column.pszText = const_cast<LPWSTR>(L"Действие");
        ListView_InsertColumn(list_, 2, &column);
        column.cx = 400;
        column.pszText = const_cast<LPWSTR>(L"Объект");
        ListView_InsertColumn(list_, 3, &column);
        column.cx = 300;
        column.pszText = const_cast<LPWSTR>(L"Подробности");
        ListView_InsertColumn(list_, 4, &column);
        ListView_SetItemCountEx(list_, 0, 0);

        versionLabel_ = CreateWindowExW(0, L"STATIC", WATCHPROG_VERSION_FULL,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_CENTERIMAGE, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_VERSION_LABEL), instance_, nullptr);
        footerStatus_ = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_CENTERIMAGE, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_FOOTER_STATUS), instance_, nullptr);
        footerCounts_ = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_NOPREFIX | SS_CENTERIMAGE, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(IDC_FOOTER_COUNTS), instance_, nullptr);
    }

    void ApplyButtonMode() {
        for (HWND button : { btnOpen_, btnRerun_, btnStop_ }) {
            if (!button) continue;
            LONG_PTR style = GetWindowLongPtrW(button, GWL_STYLE);
            LONG_PTR type = g_theme.dark ? BS_OWNERDRAW : BS_PUSHBUTTON;
            if ((style & 0xF) == type) continue;
            style = (style & ~static_cast<LONG_PTR>(0xF)) | type;
            SetWindowLongPtrW(button, GWL_STYLE, style);
            SetWindowPos(button, nullptr, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
            InvalidateRect(button, nullptr, TRUE);
        }
    }

    void ApplyFonts() {
        HFONT font = g_theme.fontUi;
        for (HWND control : { btnOpen_, btnRerun_, btnStop_ }) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(list_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(versionLabel_, WM_SETFONT, reinterpret_cast<WPARAM>(g_theme.fontSmall), TRUE);
        SendMessageW(footerStatus_, WM_SETFONT, reinterpret_cast<WPARAM>(g_theme.fontSmall), TRUE);
        SendMessageW(footerCounts_, WM_SETFONT, reinterpret_cast<WPARAM>(g_theme.fontSmall), TRUE);
    }

    void ApplyColors() {
        if (!list_) return;
        ListView_SetBkColor(list_, g_theme.listBg);
        ListView_SetTextBkColor(list_, g_theme.listBg);
        ListView_SetTextColor(list_, g_theme.text);
        SetWindowTheme(list_, g_theme.dark ? L"DarkMode_Explorer" : L"Explorer", nullptr);
        HWND header = ListView_GetHeader(list_);
        if (header) SetWindowTheme(header, g_theme.dark ? L"DarkMode_ItemsView" : L"Explorer", nullptr);
        InvalidateRect(list_, nullptr, TRUE);
        for (HWND button : { btnOpen_, btnRerun_, btnStop_ }) {
            if (button) InvalidateRect(button, nullptr, TRUE);
        }
        if (hwnd_) InvalidateRect(hwnd_, nullptr, TRUE);
    }

    void DrawButton(const DRAWITEMSTRUCT* item) {
        if (!item || (item->CtlID != IDC_OPEN_BUTTON && item->CtlID != IDC_RERUN_BUTTON &&
                      item->CtlID != IDC_STOP_BUTTON)) {
            return;
        }
        HDC dc = item->hDC;
        RECT rc = item->rcItem;
        bool disabled = (item->itemState & ODS_DISABLED) != 0;
        bool pressed = (item->itemState & ODS_SELECTED) != 0;
        bool primary = item->CtlID == IDC_OPEN_BUTTON;
        bool dark = g_theme.dark;

        HBRUSH background = CreateSolidBrush(g_theme.windowBg);
        FillRect(dc, &rc, background);
        DeleteObject(background);

        COLORREF primaryFill = dark ? RGB(22, 96, 155) : g_theme.accent;
        COLORREF fill = primary ? primaryFill : g_theme.panelBg;
        COLORREF border = primary ? primaryFill : g_theme.border;
        COLORREF text = primary ? RGB(255, 255, 255) : g_theme.text;
        if (disabled) {
            fill = g_theme.windowBg;
            border = g_theme.border;
            text = g_theme.muted;
        } else if (pressed) {
            fill = primary ? (dark ? RGB(12, 70, 118) : RGB(0, 72, 142)) : g_theme.selectionBg;
            border = primary ? fill : g_theme.accent;
            text = RGB(255, 255, 255);
        }
        HBRUSH fillBrush = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, 1, border);
        HGDIOBJ oldBrush = SelectObject(dc, fillBrush);
        HGDIOBJ oldPen = SelectObject(dc, pen);
        RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, g_theme.Scale(8), g_theme.Scale(8));
        SelectObject(dc, oldBrush);
        SelectObject(dc, oldPen);
        DeleteObject(fillBrush);
        DeleteObject(pen);

        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, text);
        HFONT font = g_theme.fontUi;
        HGDIOBJ oldFont = SelectObject(dc, font);
        wchar_t label[128] = {};
        GetWindowTextW(item->hwndItem, label, 128);
        RECT textRect = rc;
        DrawTextW(dc, label, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        if (item->itemState & ODS_FOCUS) {
            RECT focus = rc;
            InflateRect(&focus, -g_theme.Scale(4), -g_theme.Scale(4));
            DrawFocusRect(dc, &focus);
        }
        SelectObject(dc, oldFont);
    }

    void Layout() {
        if (!hwnd_ || !list_) return;
        RECT client = {};
        GetClientRect(hwnd_, &client);
        int margin = g_theme.Scale(24);
        int headerHeight = g_theme.Scale(152);
        int footerHeight = g_theme.Scale(34);
        int footerTop = client.bottom - footerHeight;
        int buttonW = g_theme.Scale(136);
        int buttonH = g_theme.Scale(30);
        int gap = g_theme.Scale(8);
        int buttonY = g_theme.Scale(19);
        int x = client.right - margin - buttonW;
        SaveButtonPosition(btnStop_, x, buttonY, buttonW, buttonH);
        x -= buttonW + gap;
        SaveButtonPosition(btnRerun_, x, buttonY, buttonW, buttonH);
        x -= buttonW + gap;
        SaveButtonPosition(btnOpen_, x, buttonY, buttonW, buttonH);

        int footerLabelY = footerTop + g_theme.Scale(4);
        int footerLabelH = footerHeight - g_theme.Scale(4);
        SetWindowPos(versionLabel_, nullptr, margin, footerLabelY, g_theme.Scale(210), footerLabelH,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        int countsWidth = g_theme.Scale(310);
        SetWindowPos(footerCounts_, nullptr, client.right - margin - countsWidth, footerLabelY,
                     countsWidth, footerLabelH, SWP_NOZORDER | SWP_NOACTIVATE);
        int statusX = margin + g_theme.Scale(218);
        int statusWidth = client.right - margin - countsWidth - statusX;
        if (statusWidth < g_theme.Scale(150)) statusWidth = g_theme.Scale(150);
        SetWindowPos(footerStatus_, nullptr, statusX, footerLabelY, statusWidth, footerLabelH,
                     SWP_NOZORDER | SWP_NOACTIVATE);

        int listTop = headerHeight + g_theme.Scale(46);
        int listBottom = footerTop - g_theme.Scale(10);
        int listWidth = client.right - margin * 2;
        int listHeight = listBottom - listTop;
        if (listHeight < g_theme.Scale(100)) listHeight = g_theme.Scale(100);
        SetWindowPos(list_, nullptr, margin, listTop, listWidth, listHeight,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        int scrollbar = GetSystemMetricsForDpi(SM_CXVSCROLL, g_theme.dpi);
        int available = listWidth - scrollbar - g_theme.Scale(8);
        int timeW = g_theme.Scale(76);
        int categoryW = g_theme.Scale(108);
        int actionW = g_theme.Scale(190);
        int objectW = g_theme.Scale(400);
        int detailsW = available - timeW - categoryW - actionW - objectW;
        if (detailsW < g_theme.Scale(180)) {
            objectW = available - timeW - categoryW - actionW - g_theme.Scale(180);
            detailsW = available - timeW - categoryW - actionW - objectW;
        }
        ListView_SetColumnWidth(list_, 0, timeW);
        ListView_SetColumnWidth(list_, 1, categoryW);
        ListView_SetColumnWidth(list_, 2, actionW);
        ListView_SetColumnWidth(list_, 3, objectW);
        ListView_SetColumnWidth(list_, 4, detailsW);
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void SaveButtonPosition(HWND button, int x, int y, int w, int h) {
        SetWindowPos(button, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    }

    void OnPaint() {
        PAINTSTRUCT ps = {};
        HDC dc = BeginPaint(hwnd_, &ps);
        RECT client = {};
        GetClientRect(hwnd_, &client);
        FillRect(dc, &client, g_theme.windowBrush);
        SetBkMode(dc, TRANSPARENT);

        int margin = g_theme.Scale(24);
        int headerH = g_theme.Scale(152);
        RECT titleRect = { margin, g_theme.Scale(14), client.right - g_theme.Scale(500), g_theme.Scale(48) };
        SelectObject(dc, g_theme.fontTitle);
        SetTextColor(dc, g_theme.text);
        DrawTextW(dc, L"WatchProg", -1, &titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
        RECT subtitleRect = { margin, g_theme.Scale(47), client.right - g_theme.Scale(500), g_theme.Scale(68) };
        SelectObject(dc, g_theme.fontSmall);
        SetTextColor(dc, g_theme.muted);
        DrawTextW(dc, L"Наблюдение за действиями программы", -1, &subtitleRect,
                  DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

        RECT drop = { margin, g_theme.Scale(78), client.right - margin, g_theme.Scale(144) };
        FillRect(dc, &drop, g_theme.panelBrush);
        HPEN borderPen = CreatePen(PS_SOLID, 1, g_theme.border);
        HGDIOBJ oldPen = SelectObject(dc, borderPen);
        HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, drop.left, drop.top, drop.right, drop.bottom, g_theme.Scale(8), g_theme.Scale(8));
        SelectObject(dc, oldBrush);
        SelectObject(dc, oldPen);
        DeleteObject(borderPen);

        RECT text = { drop.left + g_theme.Scale(16), drop.top + g_theme.Scale(8),
                      drop.right - g_theme.Scale(16), drop.top + g_theme.Scale(36) };
        RECT subText = { text.left, drop.top + g_theme.Scale(34), text.right, drop.bottom - g_theme.Scale(6) };
        if (targetPath_.empty()) {
            SelectObject(dc, g_theme.fontUiBold);
            SetTextColor(dc, g_theme.text);
            DrawTextW(dc, L"Перетащите файл в окно", -1, &text,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(dc, g_theme.fontSmall);
            SetTextColor(dc, g_theme.muted);
            DrawTextW(dc, SupportedExtensionsText().c_str(), -1, &subText,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        } else {
            SelectObject(dc, g_theme.fontUiBold);
            SetTextColor(dc, g_theme.text);
            DrawTextW(dc, targetPath_.c_str(), -1, &text,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
            SelectObject(dc, g_theme.fontSmall);
            SetTextColor(dc, g_theme.muted);
            std::wstring info = L"Тип: " + UpperExtension(targetExt_) + L"   Размер: " +
                                FormatBytes(targetSize_) + L"   Состояние: " + StateCaption();
            DrawTextW(dc, info.c_str(), -1, &subText,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        }
        // Divider under the header.
        RECT divider = { margin, headerH, client.right - margin, headerH + 1 };
        FillRect(dc, &divider, g_theme.panelBrush);

        RECT section = { margin, headerH + g_theme.Scale(12), client.right - margin, headerH + g_theme.Scale(38) };
        SelectObject(dc, g_theme.fontUiBold);
        SetTextColor(dc, g_theme.text);
        DrawTextW(dc, L"Журнал действий", -1, &section,
                  DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
        std::wstring countText = L"Событий: " + std::to_wstring(events_.size()) +
                                 L"   Показано: " + std::to_wstring(visible_.size());
        SelectObject(dc, g_theme.fontSmall);
        SetTextColor(dc, g_theme.muted);
        DrawTextW(dc, countText.c_str(), -1, &section,
                  DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

        int footerTop = client.bottom - g_theme.Scale(34);
        RECT footer = { 0, footerTop, client.right, client.bottom };
        FillRect(dc, &footer, g_theme.windowBrush);
        RECT footerLine = { margin, footerTop, client.right - margin, footerTop + 1 };
        HBRUSH lineBrush = CreateSolidBrush(g_theme.border);
        FillRect(dc, &footerLine, lineBrush);
        DeleteObject(lineBrush);
        EndPaint(hwnd_, &ps);
    }

    std::wstring StateCaption() const {
        if (monitoringActive_ && !completed_) return L"Наблюдение";
        if (completed_) return L"Программа завершила работу";
        if (starting_) {
            AgentSnapshot snap = agent_->Snapshot();
            if (snap.state == AgentRunState::Starting) return L"Подготовка (запрос прав)";
            return L"Запуск";
        }
        if (!currentError_.empty()) return L"Ошибка";
        if (!targetPath_.empty()) return L"Остановлено";
        return L"Готово";
    }

    void OnDrop(HDROP drop) {
        UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        if (count != 1) {
            DragFinish(drop);
            ShowInfo(hwnd_, L"Перетащите только один файл.", MB_ICONWARNING);
            return;
        }
        UINT length = DragQueryFileW(drop, 0, nullptr, 0);
        std::wstring path(length + 1, L'\0');
        DragQueryFileW(drop, 0, path.data(), length + 1);
        path.resize(length);
        DragFinish(drop);
        StartFile(path);
    }

    void OnCommand(UINT id, UINT code) {
        (void)code;
        switch (id) {
            case IDM_FILE_OPEN:
            case IDC_OPEN_BUTTON:
                OpenFileDialog();
                break;
            case IDM_FILE_RERUN:
            case IDC_RERUN_BUTTON:
                if (!targetPath_.empty()) StartFile(targetPath_);
                break;
            case IDM_FILE_STOP:
            case IDC_STOP_BUTTON:
                StopAnalysis();
                break;
            case IDM_FILE_CLEAR:
                ClearLog();
                break;
            case IDM_FILE_EXPORT:
                if (events_.empty()) {
                    ShowInfo(hwnd_, L"Журнал пуст — сохранять нечего.", MB_ICONINFORMATION);
                } else if (Report_Save(hwnd_, events_, targetPath_)) {
                    SetStatus(L"Журнал сохранён.");
                }
                break;
            case IDM_FILE_EXIT:
                PostMessageW(hwnd_, WM_CLOSE, 0, 0);
                break;
            case IDM_VIEW_FILES:
                filter_.enabled[CatFile] = !filter_.enabled[CatFile];
                SyncFilters();
                break;
            case IDM_VIEW_REGISTRY:
                filter_.enabled[CatRegistry] = !filter_.enabled[CatRegistry];
                SyncFilters();
                break;
            case IDM_VIEW_TASKS:
                filter_.enabled[CatTasks] = !filter_.enabled[CatTasks];
                SyncFilters();
                break;
            case IDM_VIEW_PROCESSES:
                filter_.enabled[CatProcess] = !filter_.enabled[CatProcess];
                SyncFilters();
                break;
            case IDM_VIEW_NETWORK:
                filter_.enabled[CatNetwork] = !filter_.enabled[CatNetwork];
                SyncFilters();
                break;
            case IDM_VIEW_AUTOSCROLL:
                autoScroll_ = !autoScroll_;
                CheckMenuItem(menu_, IDM_VIEW_AUTOSCROLL, MF_BYCOMMAND | (autoScroll_ ? MF_CHECKED : MF_UNCHECKED));
                break;
            case IDM_HELP_HOW:
                ShowHowItWorks();
                break;
            case IDM_HELP_ABOUT:
                ShowInfo(hwnd_,
                    L"WatchProg V1.03-rc-023\n\n"
                    L"Инструмент наблюдения за действиями программ в Windows.\n"
                    L"Работает на встроенном механизме трассировки ETW.",
                    MB_ICONINFORMATION);
                break;
            default:
                break;
        }
    }

    void ShowHowItWorks() {
        ShowInfo(hwnd_,
            L"WatchProg запускает выбранный файл и показывает его действия в реальном времени.\n\n"
            L"Наблюдаются:\n"
            L"— создание, изменение, удаление и переименование файлов и папок;\n"
            L"— создание, изменение и удаление разделов и параметров реестра;\n"
            L"— создание, изменение, удаление и запуск заданий планировщика;\n"
            L"— запуск и завершение процессов;\n"
            L"— сетевые подключения, передача данных и DNS-запросы.\n\n"
            L"Для системной трассировки требуется подтверждение прав администратора. "
            L"Интерфейс остаётся непривилегированным: отдельная служба наблюдения запускается по запросу.\n\n"
            L"Внимание: выбранный файл действительно запускается с повышенными правами. "
            L"Используйте только доверенные файлы или виртуальную машину.\n\n"
            L"Время событий показывается по локальным часам с точностью до секунды.",
            MB_ICONWARNING);
    }

    void OnClose() {
        if (monitoringActive_ && !completed_) {
            if (MessageBoxW(hwnd_,
                    L"Наблюдение ещё выполняется. Закрыть WatchProg?\n\n"
                    L"Запущенная программа продолжит работу, но сбор действий прекратится.",
                    L"WatchProg", MB_YESNO | MB_ICONQUESTION) != IDYES) {
                return;
            }
        }
        KillTimer(hwnd_, kPollTimer);
        if (agent_) agent_->Shutdown();
        DestroyWindow(hwnd_);
    }

    LRESULT OnNotify(NMHDR* header) {
        if (!header) return 0;
        if (header->hwndFrom == list_) {
            if (header->code == LVN_GETDISPINFOW) {
                auto* info = reinterpret_cast<NMLVDISPINFOW*>(header);
                if (!(info->item.mask & LVIF_TEXT)) return 0;
                size_t index = static_cast<size_t>(info->item.iItem);
                if (index >= visible_.size()) return 0;
                const LogEvent& event = events_[visible_[index]];
                const std::wstring* text = nullptr;
                switch (info->item.iSubItem) {
                    case 0: {
                        thread_local std::wstring timeText;
                        timeText = FormatDateTime(event.time, true);
                        text = &timeText;
                        break;
                    }
                    case 1: {
                        thread_local std::wstring category;
                        category = CategoryName(event.category);
                        text = &category;
                        break;
                    }
                    case 2: text = &event.action; break;
                    case 3: text = &event.object; break;
                    case 4: text = &event.details; break;
                    default: break;
                }
                if (text) {
                    wcsncpy(info->item.pszText, text->c_str(), info->item.cchTextMax - 1);
                    info->item.pszText[info->item.cchTextMax - 1] = L'\0';
                }
                return 0;
            }
            if (header->code == NM_CUSTOMDRAW) {
                auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(header);
                switch (draw->nmcd.dwDrawStage) {
                    case CDDS_PREPAINT:
                        return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
                    case CDDS_ITEMPREPAINT:
                        draw->clrText = g_theme.text;
                        draw->clrTextBk = g_theme.listBg;
                        return CDRF_NOTIFYSUBITEMDRAW;
                    case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
                        size_t index = static_cast<size_t>(draw->nmcd.dwItemSpec);
                        bool selected = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
                        if (selected) {
                            draw->clrText = g_theme.selectionText;
                            draw->clrTextBk = g_theme.selectionBg;
                        } else if (index < visible_.size()) {
                            const LogEvent& event = events_[visible_[index]];
                            if (draw->iSubItem == 1) draw->clrText = g_theme.category[event.category];
                            else draw->clrText = g_theme.text;
                            draw->clrTextBk = g_theme.listBg;
                        }
                        return CDRF_NEWFONT;
                    }
                    case CDDS_POSTPAINT:
                        DrawEmptyList(draw->nmcd.hdc);
                        return CDRF_DODEFAULT;
                    default:
                        break;
                }
            }
        }
        return 0;
    }

    void DrawEmptyList(HDC dc) {
        if (!visible_.empty() || !list_) return;
        RECT rc = {};
        GetClientRect(list_, &rc);
        rc.top += g_theme.Scale(70);
        wchar_t primary[256] = {};
        wchar_t secondary[256] = {};
        if (events_.empty()) {
            wcscpy(primary, L"Перетащите файл в окно");
            wcscpy(secondary, L"Действия запущенной программы появятся здесь");
        } else {
            wcscpy(primary, L"Нет событий по выбранным фильтрам");
            wcscpy(secondary, L"Включите нужные категории в меню «Вид»");
        }
        SelectObject(dc, g_theme.fontUiBold);
        SetTextColor(dc, g_theme.muted);
        SetBkMode(dc, TRANSPARENT);
        RECT first = rc;
        first.bottom = rc.top + g_theme.Scale(24);
        DrawTextW(dc, primary, -1, &first, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, g_theme.fontSmall);
        RECT second = rc;
        second.top += g_theme.Scale(28);
        second.bottom = second.top + g_theme.Scale(22);
        DrawTextW(dc, secondary, -1, &second, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    void OpenFileDialog() {
        if (starting_ || (monitoringActive_ && !completed_)) {
            ShowInfo(hwnd_, L"Сначала остановите текущее наблюдение.", MB_ICONINFORMATION);
            return;
        }
        wchar_t path[32768] = {};
        OPENFILENAMEW dialog = {};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = hwnd_;
        dialog.lpstrFilter =
            L"Поддерживаемые файлы\0*.exe;*.msi;*.appx;*.appinstaller;*.msix;*.msixbundle;*.appxbundle;*.com;*.bat;*.vbs;*.ps1;*.dll;*.vbe;*.cmd;*.cpl;*.msc;*.scr\0"
            L"Все файлы\0*.*\0";
        dialog.lpstrFile = path;
        dialog.nMaxFile = 32768;
        dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
        dialog.lpstrTitle = L"Выберите файл для наблюдения";
        if (GetOpenFileNameW(&dialog)) StartFile(path);
    }

    void StartFile(const std::wstring& path) {
        if (starting_ || pendingStart_) {
            ShowInfo(hwnd_, L"Дождитесь завершения текущей подготовки наблюдения.", MB_ICONINFORMATION);
            return;
        }
        if (monitoringActive_ && !completed_) {
            ShowInfo(hwnd_, L"Наблюдение уже выполняется. Сначала нажмите «Остановить».", MB_ICONINFORMATION);
            return;
        }
        AgentSnapshot snapshot = agent_->Snapshot();
        if (snapshot.state == AgentRunState::Starting) {
            ShowInfo(hwnd_, L"Служба наблюдения уже запускается. Подождите несколько секунд.", MB_ICONINFORMATION);
            return;
        }
        std::wstring full = FullPath(Trim(path));
        if (!FileExists(full) || IsDirectory(full)) {
            ShowInfo(hwnd_, L"Файл не найден: " + full, MB_ICONERROR);
            return;
        }
        std::wstring ext = ExtensionOf(full);
        if (!IsSupportedExtension(ext)) {
            ShowInfo(hwnd_,
                L"Формат «" + ext + L"» не поддерживается.\n\nПоддерживаются: " + SupportedExtensionsText(),
                MB_ICONWARNING);
            return;
        }

        // A new run starts with a clean page. The agent stops a previous completed session itself.
        inbox_.clear();
        events_.clear();
        visible_.clear();
        categoryCounts_.fill(0);
        listedEvents_ = 0;
        uiDropped_ = 0;
        ListView_SetItemCountEx(list_, 0, 0);
        if (agent_) agent_->SetExpectedSession(0);
        targetPath_ = full;
        targetExt_ = ext;
        targetSize_ = FileSizeOf(full);
        targetLoaded_ = NowFileTime();
        currentError_.clear();
        completed_ = false;
        pendingStart_ = true;
        starting_ = true;
        stopRequested_ = false;
        cancelPending_ = false;
        startSent_ = false;
        monitoringActive_ = false;
        pendingSession_ = ++nextSession_;
        if (pendingSession_ == 0) pendingSession_ = ++nextSession_;
        SetStatus(L"Подготовка службы наблюдения. Подтвердите запрос прав администратора.");
        UpdateInterface();

        if (snapshot.state != AgentRunState::Ready) {
            std::wstring error;
            if (!agent_->Launch(error)) {
                starting_ = false;
                pendingStart_ = false;
                currentError_ = error;
                SetStatus(FirstLine(error));
                ShowInfo(hwnd_, error, MB_ICONERROR);
                UpdateInterface();
                InvalidateRect(hwnd_, nullptr, FALSE);
                return;
            }
            SetStatus(L"Подготовка службы наблюдения. Подтвердите запрос прав администратора.");
        } else {
            SendPendingStart();
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        UpdateInterface();
    }

    void SendPendingStart() {
        if (!pendingStart_ || !agent_) return;
        AgentSnapshot snapshot = agent_->Snapshot();
        if (snapshot.state != AgentRunState::Ready || cancelPending_ || stopRequested_) return;
        std::wstring error;
        if (!agent_->SendStart(pendingSession_, targetPath_, error)) {
            pendingStart_ = false;
            starting_ = false;
            currentError_ = error;
            SetStatus(FirstLine(error));
            ShowInfo(hwnd_, error, MB_ICONERROR);
        } else {
            pendingStart_ = false;
            currentSession_ = pendingSession_;
            startSent_ = true;
            SetStatus(L"Запуск программы…");
        }
        UpdateInterface();
    }

    void StopAnalysis() {
        if (!agent_) return;
        AgentSnapshot snapshot = agent_->Snapshot();
        bool canSend = snapshot.state == AgentRunState::Ready;
        bool needStop = startSent_ || monitoringActive_;
        pendingStart_ = false;
        cancelPending_ = true;
        if (needStop && canSend) {
            std::wstring error;
            if (!agent_->SendStop(error)) {
                currentError_ = error;
                SetStatus(FirstLine(error));
                starting_ = false;
                monitoringActive_ = false;
                completed_ = false;
                startSent_ = false;
                stopRequested_ = false;
                UpdateInterface();
                ShowInfo(hwnd_, error, MB_ICONERROR);
                return;
            }
            stopRequested_ = true;
            SetStatus(L"Остановка наблюдения…");
        } else if (!canSend && snapshot.state == AgentRunState::Starting) {
            starting_ = false;
            SetStatus(L"Подготовка отменена. Если запрос прав появился, отмените его.");
        } else {
            starting_ = false;
            monitoringActive_ = false;
            completed_ = false;
            startSent_ = false;
            stopRequested_ = false;
            SetStatus(L"Наблюдение остановлено.");
        }
        UpdateInterface();
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void ClearLog() {
        if (agent_) agent_->DrainEvents();
        inbox_.clear();
        events_.clear();
        visible_.clear();
        categoryCounts_.fill(0);
        listedEvents_ = 0;
        uiDropped_ = 0;
        ListView_SetItemCountEx(list_, 0, 0);
        if (monitoringActive_) SetStatus(L"Журнал очищен. Наблюдение продолжается.");
        else SetStatus(L"Журнал очищен.");
        InvalidateRect(hwnd_, nullptr, FALSE);
        UpdateInterface();
    }

    void SyncFilters() {
        CheckMenuItem(menu_, IDM_VIEW_FILES, MF_BYCOMMAND | (filter_.enabled[CatFile] ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_REGISTRY, MF_BYCOMMAND | (filter_.enabled[CatRegistry] ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_TASKS, MF_BYCOMMAND | (filter_.enabled[CatTasks] ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_PROCESSES, MF_BYCOMMAND | (filter_.enabled[CatProcess] ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_NETWORK, MF_BYCOMMAND | (filter_.enabled[CatNetwork] ? MF_CHECKED : MF_UNCHECKED));
        RebuildVisible();
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void RebuildVisible() {
        visible_.clear();
        visible_.reserve(events_.size());
        for (size_t i = 0; i < events_.size(); ++i) {
            if (filter_.Matches(events_[i].category)) visible_.push_back(i);
        }
        ListView_SetItemCountEx(list_, static_cast<int>(visible_.size()), 0);
        if (autoScroll_ && !visible_.empty()) ListView_EnsureVisible(list_, static_cast<int>(visible_.size()) - 1, FALSE);
        UpdateFooterCounts();
    }

    void PollAgent() {
        if (!agent_) return;
        AgentSnapshot snapshot = agent_->Snapshot();
        auto batch = agent_->DrainEvents();
        if (!batch.empty()) {
            for (auto& event : batch) {
                if (inbox_.size() > 400000) {
                    ++uiDropped_;
                    break;
                }
                inbox_.push_back(std::move(event));
            }
        }
        if (snapshot.state != lastAgentState_) {
            lastAgentState_ = snapshot.state;
            if (snapshot.state == AgentRunState::Failed) {
                lastStatusSequence_ = snapshot.statusSequence;
                starting_ = false;
                pendingStart_ = false;
                startSent_ = false;
                monitoringActive_ = false;
                completed_ = false;
                stopRequested_ = false;
                currentError_ = FirstLine(snapshot.error);
                SetStatus(currentError_.empty() ? L"Не удалось запустить службу наблюдения." : currentError_);
                ShowInfo(hwnd_, snapshot.error.empty() ?
                    L"Не удалось запустить службу наблюдения." : snapshot.error, MB_ICONERROR);
            } else if (snapshot.state == AgentRunState::Disconnected) {
                bool wasActive = monitoringActive_ || starting_;
                starting_ = false;
                pendingStart_ = false;
                startSent_ = false;
                monitoringActive_ = false;
                completed_ = false;
                stopRequested_ = false;
                currentError_ = L"Связь со службой наблюдения потеряна.";
                SetStatus(currentError_);
                if (wasActive) {
                    ShowInfo(hwnd_, L"Связь со службой наблюдения потеряна. Перетащите файл ещё раз, чтобы перезапустить наблюдение.", MB_ICONERROR);
                }
            } else if (snapshot.state == AgentRunState::Starting) {
                if (starting_ && !cancelPending_) {
                    SetStatus(L"Подготовка службы наблюдения. Подтвердите запрос прав администратора.");
                }
            }
        }
        if (snapshot.state == AgentRunState::Ready && snapshot.statusSequence != lastStatusSequence_) {
            lastStatusSequence_ = snapshot.statusSequence;
            const std::wstring& status = snapshot.status;
            if (status == L"started") {
                starting_ = false;
                monitoringActive_ = true;
                completed_ = false;
                pendingStart_ = false;
                startSent_ = true;
                stopRequested_ = false;
                currentError_.clear();
                SetStatus(L"Наблюдение. Действия программы появляются в журнале.");
            } else if (status == L"completed") {
                starting_ = false;
                pendingStart_ = false;
                completed_ = true;
                stopRequested_ = false;
                SetStatus(snapshot.message.empty() ? L"Программа завершила работу." : snapshot.message);
            } else if (status == L"stopped") {
                starting_ = false;
                pendingStart_ = false;
                monitoringActive_ = false;
                completed_ = false;
                startSent_ = false;
                stopRequested_ = false;
                cancelPending_ = false;
                currentError_.clear();
                SetStatus(L"Наблюдение остановлено. Перетащите другой файл.");
            } else if (status == L"error") {
                bool wasStarting = starting_ || pendingStart_;
                starting_ = false;
                pendingStart_ = false;
                monitoringActive_ = false;
                completed_ = false;
                startSent_ = false;
                stopRequested_ = false;
                currentError_ = FirstLine(snapshot.message.empty() ? L"Ошибка запуска." : snapshot.message);
                SetStatus(currentError_);
                if (wasStarting) ShowInfo(hwnd_, snapshot.message.empty() ? currentError_ : snapshot.message, MB_ICONERROR);
            } else if (status == L"ready") {
                if (!starting_ && !monitoringActive_ && !targetPath_.empty() && completed_) {
                    SetStatus(L"Служба наблюдения готова.");
                }
            }
        }
        if (snapshot.state == AgentRunState::Ready && pendingStart_ && !cancelPending_ && !stopRequested_) {
            SendPendingStart();
        }
        ProcessInbox();
        UpdateInterface();
    }

    void ProcessInbox() {
        if (inbox_.empty() || !list_) return;
        size_t processed = 0;
        size_t oldVisible = visible_.size();
        while (!inbox_.empty() && processed < kEventsPerTick) {
            LogEvent event = std::move(inbox_.front());
            inbox_.pop_front();
            ++processed;
            if (events_.size() >= kMaxUiEvents) {
                ++uiDropped_;
                continue;
            }
            size_t index = events_.size();
            if (event.category < 0 || event.category >= CatCount) event.category = CatSystem;
            ++categoryCounts_[event.category];
            events_.push_back(std::move(event));
            if (filter_.Matches(events_.back().category)) visible_.push_back(index);
        }
        listedEvents_ = events_.size();
        ListView_SetItemCountEx(list_, static_cast<int>(visible_.size()), 0);
        if (oldVisible == 0 && !visible_.empty()) {
            ListView_SetItemState(list_, static_cast<int>(-1), 0, LVIS_SELECTED | LVIS_FOCUSED);
        }
        if (autoScroll_ && visible_.size() > oldVisible && !visible_.empty()) {
            ListView_EnsureVisible(list_, static_cast<int>(visible_.size()) - 1, FALSE);
        }
        UpdateFooterCounts();
        RECT client = {};
        GetClientRect(hwnd_, &client);
        int headerH = g_theme.Scale(152);
        RECT countsRect = { client.right - g_theme.Scale(420), headerH + g_theme.Scale(8),
                            client.right - g_theme.Scale(24), headerH + g_theme.Scale(42) };
        InvalidateRect(hwnd_, &countsRect, FALSE);
    }

    void UpdateInterface() {
        if (!hwnd_) return;
        bool openAllowed = !starting_ && !(monitoringActive_ && !completed_);
        bool stopAllowed = (starting_ || monitoringActive_) && !stopRequested_;
        bool rerunAllowed = openAllowed && !targetPath_.empty();
        if (IsWindowEnabled(btnOpen_) != openAllowed) EnableWindow(btnOpen_, openAllowed);
        if (IsWindowEnabled(btnStop_) != stopAllowed) EnableWindow(btnStop_, stopAllowed);
        if (IsWindowEnabled(btnRerun_) != rerunAllowed) EnableWindow(btnRerun_, rerunAllowed);
        int menuState = (openAllowed ? 1 : 0) | (rerunAllowed ? 2 : 0) | (stopAllowed ? 4 : 0) |
                        (!events_.empty() ? 8 : 0) | ((!events_.empty() || !inbox_.empty()) ? 16 : 0);
        if (menu_ && menuState != lastMenuState_) {
            lastMenuState_ = menuState;
            EnableMenuItem(menu_, IDM_FILE_OPEN, MF_BYCOMMAND | (openAllowed ? MF_ENABLED : MF_GRAYED));
            EnableMenuItem(menu_, IDM_FILE_RERUN, MF_BYCOMMAND | (rerunAllowed ? MF_ENABLED : MF_GRAYED));
            EnableMenuItem(menu_, IDM_FILE_STOP, MF_BYCOMMAND | (stopAllowed ? MF_ENABLED : MF_GRAYED));
            EnableMenuItem(menu_, IDM_FILE_EXPORT, MF_BYCOMMAND | ((menuState & 8) ? MF_ENABLED : MF_GRAYED));
            EnableMenuItem(menu_, IDM_FILE_CLEAR, MF_BYCOMMAND | ((menuState & 16) ? MF_ENABLED : MF_GRAYED));
        }
        SetIfTextDiffers(footerStatus_, statusText_);
    }

    void UpdateFooterCounts() {
        if (!footerCounts_) return;
        std::wstring text = L"Событий: " + std::to_wstring(events_.size()) +
                            L"   Показано: " + std::to_wstring(visible_.size());
        if (uiDropped_ > 0 || listedEvents_ > events_.size()) {
            text += L"   Потеряно: " + std::to_wstring(uiDropped_);
        }
        SetIfTextDiffers(footerCounts_, text);
    }

    void SetStatus(const std::wstring& status) {
        if (status == statusText_) {
            if (footerStatus_) SetIfTextDiffers(footerStatus_, statusText_);
            return;
        }
        statusText_ = status;
        if (footerStatus_) SetIfTextDiffers(footerStatus_, statusText_);
        if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
    }

private:
    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    HWND list_ = nullptr;
    HWND btnOpen_ = nullptr;
    HWND btnRerun_ = nullptr;
    HWND btnStop_ = nullptr;
    HWND versionLabel_ = nullptr;
    HWND footerStatus_ = nullptr;
    HWND footerCounts_ = nullptr;
    HMENU menu_ = nullptr;
    int dpi_ = 96;

    AgentClient* agent_ = nullptr;
    EventFilter filter_;
    bool autoScroll_ = true;

    std::vector<LogEvent> events_;
    std::vector<size_t> visible_;
    std::deque<LogEvent> inbox_;
    std::array<unsigned long long, CatCount> categoryCounts_{};
    size_t listedEvents_ = 0;
    unsigned long long uiDropped_ = 0;

    std::wstring targetPath_;
    std::wstring targetExt_;
    unsigned long long targetSize_ = 0;
    FILETIME targetLoaded_{};
    std::wstring initialFile_;

    bool starting_ = false;
    bool pendingStart_ = false;
    bool startSent_ = false;
    bool monitoringActive_ = false;
    bool completed_ = false;
    bool stopRequested_ = false;
    bool cancelPending_ = false;
    unsigned nextSession_ = 0;
    unsigned currentSession_ = 0;
    unsigned pendingSession_ = 0;
    AgentRunState lastAgentState_ = AgentRunState::NotStarted;
    unsigned lastStatusSequence_ = 0;
    std::wstring statusText_;
    std::wstring currentError_;
    int lastMenuState_ = -1;
};

int RunGui(HINSTANCE instance, int showCommand, const std::wstring& initialFile) {
    AppWindow window(instance, initialFile);
    return window.Run(showCommand);
}


