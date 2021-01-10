#include "Firewall.h"
#include "Win32Exception.h"
#include "resource.h"
#include <Windows.h>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/debug_output_backend.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/trivial.hpp>

#pragma comment(lib, "LibFirewall.lib")

using namespace Win32Util;
using namespace ::WfpUtil;
namespace logging = boost::log;
namespace expr = boost::log::expressions;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

static const std::wstring STRING_BTN = L"’Ç‰Á";
static const DWORD LENGTH_BUFFER = 1024;
static DWORD itemID = 0;

INT_PTR CALLBACK DialogFunc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, (DLGPROC)DialogFunc);
    return 0;
}


INT_PTR CALLBACK DialogFunc(HWND hWndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    static HWND hWndButtonAdd = nullptr;
    static HWND hWndEditAddr = nullptr;
    static HWND hWndEditProtocol = nullptr;
    static HWND hWndList = nullptr;

    switch (message)
    {
    case WM_INITDIALOG:
        hWndButtonAdd = GetDlgItem(hWndDlg, IDC_BUTTON_ADD);
        hWndEditAddr = GetDlgItem(hWndDlg, IDC_IPADDRESS);
        hWndEditProtocol = GetDlgItem(hWndDlg, IDC_EDIT_PROTOCOL);
        hWndList = GetDlgItem(hWndDlg, IDC_LIST);

        SetWindowText(hWndButtonAdd, STRING_BTN.c_str());

        return (INT_PTR)TRUE;
    case WM_CLOSE:
        EndDialog(hWndDlg, 0);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_ADD:
            std::vector<WCHAR> sIpAddr(LENGTH_BUFFER);
            std::vector<WCHAR> sProtocol(LENGTH_BUFFER);
            GetWindowText(hWndEditAddr, sIpAddr.data(), LENGTH_BUFFER);
            GetWindowText(hWndEditProtocol, sProtocol.data(), LENGTH_BUFFER);

            std::wstring sListItem;
            sListItem = sIpAddr.data();
            sListItem += L"    ";
            sListItem += sProtocol.data();

            int pos = (int)SendMessage(hWndList, LB_ADDSTRING, 0, (LPARAM)sListItem.c_str());
            SendMessage(hWndList, LB_SETITEMDATA, pos, (LPARAM)itemID++);

            SetWindowText(hWndEditAddr, L"");
            SetWindowText(hWndEditProtocol, L"");
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}