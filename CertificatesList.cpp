#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <commctrl.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <map>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comctl32.lib")

#include "Resource.h"

#define ID_LISTVIEW 1001
#define ID_OK_BUTTON 1002
#define ID_ILK_LABEL 1003

#define WARN_DAYS 120

struct CertificateInfo {
    std::wstring subject;
    std::wstring issuer;
    FILETIME notAfter = { 0 };
    int daysToExpiration = 0; // negative if expired
};

class CertificateManager {
private:
    std::vector<CertificateInfo> certificates;

    std::wstring FileTimeToString(FILETIME ft) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        std::wostringstream ss;
        ss << std::setfill(L'0') << std::setw(2) << st.wDay << L"/"
            << std::setfill(L'0') << std::setw(2) << st.wMonth << L"/"
            << st.wYear << L" "
            << std::setfill(L'0') << std::setw(2) << st.wHour << L":"
            << std::setfill(L'0') << std::setw(2) << st.wMinute << L":"
            << std::setfill(L'0') << std::setw(2) << st.wSecond;
        return ss.str();
    }

    std::wstring ExtractSubjectName(PCCERT_CONTEXT certContext) {
        DWORD dwSize = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
        if (dwSize <= 1) return L"Unknown Subject";
        std::wstring buffer(dwSize, L'\0');
        CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &buffer[0], dwSize);
        buffer.resize(wcslen(buffer.c_str()));
        return buffer;
    }

    std::wstring ExtractIssuerName(PCCERT_CONTEXT certContext) {
        DWORD dwSize = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
        if (dwSize <= 1) return L"Unknown Issuer";
        std::wstring buffer(dwSize, L'\0');
        CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, &buffer[0], dwSize);
        buffer.resize(wcslen(buffer.c_str()));
        return buffer;
    }

    int GetDaysToExpiration(FILETIME notAfter) {
        ULARGE_INTEGER expiry{}, now{};
        expiry.LowPart = notAfter.dwLowDateTime;
        expiry.HighPart = notAfter.dwHighDateTime;

        FILETIME currentTime;
        GetSystemTimeAsFileTime(&currentTime);
        now.LowPart = currentTime.dwLowDateTime;
        now.HighPart = currentTime.dwHighDateTime;

        LONGLONG diff = (LONGLONG)(expiry.QuadPart - now.QuadPart);
        return static_cast<int>(diff / (10LL * 1000 * 1000 * 60 * 60 * 24));
    }

    void LoadCertificatesFromStore(DWORD dwFlags, LPCWSTR storeName) {
        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            NULL,
            dwFlags | CERT_STORE_OPEN_EXISTING_FLAG,
            storeName
        );

        if (!hStore) return;

        PCCERT_CONTEXT certContext = nullptr;
        while ((certContext = CertEnumCertificatesInStore(hStore, certContext)) != nullptr) {
            CertificateInfo cert;
            cert.subject = ExtractSubjectName(certContext);
            cert.issuer = ExtractIssuerName(certContext);
            cert.notAfter = certContext->pCertInfo->NotAfter;
            cert.daysToExpiration = GetDaysToExpiration(cert.notAfter);

            if (cert.issuer.find(L"Adobe") != std::wstring::npos ||
                cert.issuer.find(L"Microsoft") != std::wstring::npos ||
                cert.issuer.find(L"Apple") != std::wstring::npos ||
                cert.subject.rfind(L"trust_", 0) == 0) {
                continue;
            }
            std::wregex guidPattern(
                L"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$");
            if (std::regex_match(cert.subject, guidPattern)) continue;

            certificates.push_back(cert);
        }

        CertCloseStore(hStore, 0);
    }

public:
    void LoadAllCertificates() {
        certificates.clear();
        LoadCertificatesFromStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
        LoadCertificatesFromStore(CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

        std::map<std::pair<std::wstring, std::wstring>, CertificateInfo> latest;
        for (auto& cert : certificates) {
            auto key = std::make_pair(cert.issuer, cert.subject);
            if (latest.find(key) == latest.end() ||
                CompareFileTime(&cert.notAfter, &latest[key].notAfter) > 0) {
                latest[key] = cert;
            }
        }

        certificates.clear();
        for (auto& [k, cert] : latest) certificates.push_back(cert);

        std::sort(certificates.begin(), certificates.end(),
            [](const CertificateInfo& a, const CertificateInfo& b) {
                return CompareFileTime(&a.notAfter, &b.notAfter) < 0;
            });
    }

    std::wstring GenerateReport() {
        std::wostringstream report;
        report << L"\n===== CERTIFICADOS ATIVOS =====\n";
        for (const auto& cert : certificates) {
            if (cert.daysToExpiration >= 0) {
                report << L"Subject: " << cert.subject << L"\n"
                    << L"Issuer: " << cert.issuer << L"\n"
                    << L"Days to Expiration: " << cert.daysToExpiration << L"\n\n";
            }
        }

        report << L"===== CERTIFICADOS EXPIRADOS =====\n";
        for (const auto& cert : certificates) {
            if (cert.daysToExpiration < 0) {
                report << L"Subject: " << cert.subject << L"\n"
                    << L"Issuer: " << cert.issuer << L"\n"
                    << L"Days to Expiration: " << cert.daysToExpiration << L"\n\n";
            }
        }
        return report.str();
    }

    std::string WideToUtf8(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
            (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string result(requiredSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
            (int)wstr.size(), result.data(), requiredSize, NULL, NULL);
        return result;
    }

    bool SendReportToServer(const std::wstring& report) {
        HINTERNET hSession = WinHttpOpen(
            L"CertificateManager/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0
        );

        if (!hSession) return false;
        HINTERNET hConnect = WinHttpConnect(
            hSession, L"infopet.com.br",
            INTERNET_DEFAULT_HTTPS_PORT, 0
        );

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"POST", L"/uploadcert.php",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
        std::string reportUtf8 = WideToUtf8(report);

        BOOL result = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            (DWORD)headers.length(),
            (LPVOID)reportUtf8.data(),
            (DWORD)reportUtf8.size(),
            (DWORD)reportUtf8.size(),
            0
        );

        if (result) result = WinHttpReceiveResponse(hRequest, NULL);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result != FALSE;
    }

    void DisplayReport() {
        std::wcout << GenerateReport() << std::endl;
    }

    void CreateControls(HWND hwnd) {
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icex);

        HWND hListView = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEW,
            NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            10, 10, 900, 500,
            hwnd, (HMENU)ID_LISTVIEW, GetModuleHandle(NULL), NULL
        );

        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        HFONT hFont = CreateFont(
            18, 0, 0, 0, FW_NORMAL,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI");
        SendMessage(hListView, WM_SETFONT, (WPARAM)hFont, TRUE);

        LVCOLUMN col = { LVCF_TEXT | LVCF_WIDTH };
        col.pszText = const_cast<LPWSTR>(L"Descrição"); col.cx = 300;
        ListView_InsertColumn(hListView, 0, &col);

        col.pszText = const_cast<LPWSTR>(L"Emissor"); col.cx = 250;
        ListView_InsertColumn(hListView, 1, &col);

        col.pszText = const_cast<LPWSTR>(L"Status"); col.cx = 100;
        ListView_InsertColumn(hListView, 2, &col);

        col.pszText = const_cast<LPWSTR>(L"Dias para expirar"); col.cx = 180;
        ListView_InsertColumn(hListView, 3, &col);


        CreateWindow(
            L"BUTTON",
            L"OK",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            350, 520, 100, 30,
            hwnd, (HMENU)ID_OK_BUTTON, GetModuleHandle(NULL), NULL
        );

        CreateWindow(
            L"STATIC",
            L"by Infologika - infologika.com.br",
            WS_CHILD | WS_VISIBLE,
            560, 527, 250, 20,
            hwnd, (HMENU)ID_ILK_LABEL, GetModuleHandle(NULL), NULL
        );
    }

    void PopulateListView(HWND hwnd) {
        HWND hListView = GetDlgItem(hwnd, ID_LISTVIEW);
        int index = 0;

        for (const auto& cert : certificates) {
            LVITEM item = { 0 };
            item.mask = LVIF_TEXT;
            item.iItem = index;
            item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(cert.subject.c_str());
            ListView_InsertItem(hListView, &item);

            ListView_SetItemText(hListView, index, 1, const_cast<LPWSTR>(cert.issuer.c_str()));

            std::wstring status = cert.daysToExpiration < 0 ? L"Expirado" : (cert.daysToExpiration <= WARN_DAYS ? L"Vencendo" : L"Ativo");
            ListView_SetItemText(hListView, index, 2, const_cast<LPWSTR>(status.c_str()));

            std::wstring daysStr = cert.daysToExpiration < 0 ? L"Expirado" : std::to_wstring(cert.daysToExpiration);
            ListView_SetItemText(hListView, index, 3, const_cast<LPWSTR>(daysStr.c_str()));

            index++;
        }
    }

    void ResizeControls(HWND hwnd) {
        RECT rect;
        GetClientRect(hwnd, &rect);
        HWND hListView = GetDlgItem(hwnd, ID_LISTVIEW);
        SetWindowPos(hListView, NULL, 10, 10, rect.right - 20, rect.bottom - 60, SWP_NOZORDER);
        HWND hButton = GetDlgItem(hwnd, ID_OK_BUTTON);
        SetWindowPos(hButton, NULL, (rect.right - 100) / 2, rect.bottom - 40, 100, 30, SWP_NOZORDER);
        HWND hLabel = GetDlgItem(hwnd, ID_ILK_LABEL);
        SetWindowPos(hLabel, NULL, rect.right - 220, rect.bottom - 35, 250, 20, SWP_NOZORDER);
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        CertificateManager* pThis = nullptr;
        if (uMsg == WM_NCCREATE) {
            pThis = (CertificateManager*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
        }
        else {
            pThis = (CertificateManager*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        }
        if (pThis) return pThis->HandleMessage(hwnd, uMsg, wParam, lParam);
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    LRESULT HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            PopulateListView(hwnd);
            return 0;
        case WM_SIZE:
            ResizeControls(hwnd);
            return 0;
        case WM_NOTIFY:
        {
            LPNMHDR pnmhdr = (LPNMHDR)lParam;
            if (pnmhdr->idFrom == ID_LISTVIEW && pnmhdr->code == NM_CUSTOMDRAW) {
                return OnListViewCustomDraw((LPNMLVCUSTOMDRAW)lParam);
            }
        }
        return 0;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_OK_BUTTON) {
                PostQuitMessage(0);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    void ShowCertificateWindow() {
        WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"CertificateWindow";
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_CERTIFICATESLIST));
        wc.hIconSm = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_SMALL));
        RegisterClassEx(&wc);

        int width = 900;
        int height = 600;

        HWND hwnd = CreateWindowEx(
            0, L"CertificateWindow", L"Lista de Certificados",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
            width, height, NULL, NULL, GetModuleHandle(NULL), this
        );

        if (hwnd) {
            // ✅ Center the window:
            RECT screenRect;
            GetWindowRect(GetDesktopWindow(), &screenRect); // full desktop
            int screenWidth = screenRect.right;
            int screenHeight = screenRect.bottom;

            int x = (screenWidth - width) / 2;
            int y = (screenHeight - height) / 2;
            SetWindowPos(
                hwnd, NULL,
                x, y,
                width, height,
                SWP_NOZORDER | SWP_NOACTIVATE
            );

            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);

            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }

    LRESULT OnListViewCustomDraw(LPNMLVCUSTOMDRAW pnmcd) {
        switch (pnmcd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT: {
            int index = (int)pnmcd->nmcd.dwItemSpec;
            if (index >= 0 && index < (int)certificates.size()) {
                if (certificates[index].daysToExpiration < 0)
                    pnmcd->clrText = RGB(70, 0, 0); // dark red text for expired
                else if (certificates[index].daysToExpiration <= WARN_DAYS)
                    pnmcd->clrText = RGB(200, 50, 0); // red text for close to expire
                else
                    pnmcd->clrText = RGB(0, 120, 0); // green text for active
            }
            return CDRF_DODEFAULT;
        }
        }
        return CDRF_DODEFAULT;
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    CertificateManager certManager;

    std::wcout << L"Loading certificates..." << std::endl;
    certManager.LoadAllCertificates();

    std::wstring report = certManager.GenerateReport();
    std::wcout << report << std::endl;

    std::cout << "Sending report to server..." << std::endl;
    if (certManager.SendReportToServer(report)) {
        std::cout << "Report sent successfully." << std::endl;
    }
    else {
        std::cerr << "Failed to send report to server." << std::endl;
    }

    std::cout << "Opening certificate window..." << std::endl;
    certManager.ShowCertificateWindow();
    return 0;
}
