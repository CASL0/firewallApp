#include "Firewall.h"
#include "Win32Exception.h"
#include "resource.h"
#include <Windows.h>
#include <sstream>
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

static const std::wstring STRING_BTN_ADD = L"追加";
static const std::wstring STRING_BTN_DEL = L"削除";
static const std::wstring STRING_COMBO[] = { L"許可",L"遮断" };
static const std::wstring STRING_TEXT_ADDR = L"IPアドレス";
static const std::wstring STRING_TEXT_PROTOCOL = L"プロトコル";
static const std::wstring STRING_TEXT_ACTION = L"アクション";
static DWORD INIT_COMBO_SEL = 0;
static const DWORD LENGTH_BUFFER = 1024;
static DWORD nextItemID = 0;

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
    static HWND hWndButtonDel = nullptr;
    static HWND hWndEditAddr = nullptr;
    static HWND hWndEditProtocol = nullptr;
    static HWND hWndList = nullptr;
    static HWND hWndComboAction = nullptr;
    static HWND hWndTextAddr = nullptr;
    static HWND hWndTextProtocol = nullptr;
    static HWND hWndTextAction = nullptr;

    switch (message)
    {
    case WM_INITDIALOG:

        //UIパーツの設定

        //「追加」ボタン
        hWndButtonAdd = GetDlgItem(hWndDlg, IDC_BUTTON_ADD);
        SetWindowText(hWndButtonAdd, STRING_BTN_ADD.c_str());

        //「削除」ボタン
        hWndButtonDel = GetDlgItem(hWndDlg, IDC_BUTTON_DEL);
        SetWindowText(hWndButtonDel, STRING_BTN_DEL.c_str());

        //IPアドレス入力フォーム
        hWndEditAddr = GetDlgItem(hWndDlg, IDC_IPADDRESS);

        //プロトコル入力フォーム
        hWndEditProtocol = GetDlgItem(hWndDlg, IDC_EDIT_PROTOCOL);

        //フィルター表示用リスト
        hWndList = GetDlgItem(hWndDlg, IDC_LIST);

        //アクションコンボボックス
        hWndComboAction = GetDlgItem(hWndDlg, IDC_COMBO);
        SendMessage(hWndComboAction, CB_ADDSTRING, 0, (LPARAM)STRING_COMBO[0].c_str());
        SendMessage(hWndComboAction, CB_ADDSTRING, 0, (LPARAM)STRING_COMBO[1].c_str());
        SendMessage(hWndComboAction, CB_SETCURSEL, INIT_COMBO_SEL, 0);

        //スタティックテキスト類
        SetWindowText(hWndTextAddr, STRING_TEXT_ADDR.c_str());
        SetWindowText(hWndTextProtocol, STRING_TEXT_PROTOCOL.c_str());
        SetWindowText(hWndTextAction, STRING_TEXT_ACTION.c_str());

        return (INT_PTR)TRUE;
    case WM_CLOSE:
        EndDialog(hWndDlg, 0);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_ADD:
        {
            std::vector<WCHAR> sIpAddr(LENGTH_BUFFER);
            std::vector<WCHAR> sProtocol(LENGTH_BUFFER);
            GetWindowText(hWndEditAddr, sIpAddr.data(), LENGTH_BUFFER);
            GetWindowText(hWndEditProtocol, sProtocol.data(), LENGTH_BUFFER);
            int iCurSel = (int)SendMessage(hWndComboAction, CB_GETCURSEL, 0, 0);

            std::wstringstream ssListItem;
            ssListItem << sIpAddr.data() << L"    " << sProtocol.data() << L"    " << STRING_COMBO[iCurSel];

            SendMessage(hWndList, LB_ADDSTRING, 0, (LPARAM)ssListItem.str().c_str());

            SetWindowText(hWndEditAddr, L"");
            SetWindowText(hWndEditProtocol, L"");
            return (INT_PTR)TRUE;
        }
        case IDC_BUTTON_DEL:
        {
            //未選択の場合は-1が返ってくる
            int idx = SendMessage(hWndList, LB_GETCURSEL, 0, 0);
            if (idx == -1)
            {
                return (INT_PTR)TRUE;
            }
            int id = MessageBox(hWndDlg, L"削除しますか？", L"", MB_OKCANCEL | MB_ICONEXCLAMATION);

            if (id == IDCANCEL)
            {
                return (INT_PTR)TRUE;
            }
            SendMessage(hWndList, LB_DELETESTRING, idx, 0);
            return (INT_PTR)TRUE;        
        }
        }   //switch (LOWORD(wParam))
        break;
    }
    return (INT_PTR)FALSE;
}