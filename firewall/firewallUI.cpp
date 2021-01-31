#include "Firewall.h"
#include "Win32Exception.h"
#include "resource.h"
#include "uiConfigure.h"
#include <Windows.h>
#include <algorithm>
#include <string>
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

#define FWM_DISABLE_FORM (WM_APP + 1)
#define FWM_CHECKBOX     (FWM_DISABLE_FORM + 1)
#define FWM_IP_CHECK     (FWM_CHECKBOX + 1)
#define FWM_PORT_CHECK   (FWM_IP_CHECK + 1)

static const DWORD LENGTH_BUFFER = 1024;

static std::shared_ptr<CFirewall> pFirewall = nullptr;

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

    static HWND hWndList = nullptr;
    static HWND hWndComboAction = nullptr;
    static std::map<std::string, HWND> hWndButton;
    static std::map<std::string, HWND> hWndEdit;
    static std::map<std::string, HWND> hWndCheckBox;

    static const std::vector<std::string> IpKey = {
        "addr",
        "fqdn",
        "url",
    };

    static const std::vector<std::string> PortKey = {
        "port",
        "protocol",
        "url",
    };

    switch (message)
    {
    case WM_INITDIALOG:

        //UIパーツの設定

        {
            //フィルター表示用リスト
            hWndList = GetDlgItem(hWndDlg, IDC_LIST);

            InitButton(hWndDlg  , hWndButton);
            InitEdit(hWndDlg    , hWndEdit);
            InitCheckBox(hWndDlg, hWndCheckBox);
            InitComboBox(hWndDlg, hWndComboAction);
        }

        logging::add_common_attributes();
        logging::add_file_log(
            keywords::file_name = "firewall.log", // logを出力するファイル名
            keywords::format =
            "%Tag%: [%TimeStamp%] [%ThreadID%] %Message%" // logのフォーマット
        );

        try
        {
            pFirewall = std::make_shared<CFirewall>();
        }
        catch (std::runtime_error& e)
        {
            BOOST_LOG_TRIVIAL(trace) << "CFirewall::CFirewall failed with error: " << e.what();
            MessageBox(hWndDlg, L"ファイアウォールの初期化に失敗しました", L"", MB_ICONERROR | MB_OK);
            exit(1);
            break;
        }

        return (INT_PTR)TRUE;
    case WM_CLOSE:
        try
        {
            pFirewall->close();
        }
        catch (std::runtime_error& e)
        {
            BOOST_LOG_TRIVIAL(trace) << "CFirewall::close failed with error: " << e.what();
            MessageBox(hWndDlg, L"ファイアウォールの終了処理に失敗しました", L"", MB_ICONERROR | MB_OK);
            exit(1);
            break;
        }
        EndDialog(hWndDlg, 0);
        return (INT_PTR)TRUE;
    case FWM_IP_CHECK:
    {
        LPCSTR sKey = (LPCSTR)wParam;
        for (const auto& elem : IpKey)
        {
            if (sKey != elem)
            {
                SendMessage(hWndDlg, FWM_DISABLE_FORM, (WPARAM)elem.c_str(), 0);
            }
        }
        return (INT_PTR)TRUE;
    }
    case FWM_PORT_CHECK:
    {
        LPCSTR sKey = (LPCSTR)wParam;
        for (const auto& elem : PortKey)
        {
            if (sKey != elem)
            {
                SendMessage(hWndDlg, FWM_DISABLE_FORM, (WPARAM)elem.c_str(), 0);
            }
        }
        return (INT_PTR)TRUE;
    }
    case FWM_DISABLE_FORM:
    {
        LPCSTR sKeky = (LPCSTR)wParam;
        SendMessage(hWndCheckBox[sKeky], BM_SETCHECK   , BST_UNCHECKED, 0);
        SendMessage(hWndEdit[sKeky]    , EM_SETREADONLY, TRUE         , 0);
        return (INT_PTR)TRUE;
    }
    case FWM_CHECKBOX:
    {
        LPCSTR sKey = (LPCSTR)wParam;
        bool isChecked = BST_CHECKED == SendMessage(hWndCheckBox[sKey], BM_GETCHECK, 0, 0);

        //チェックを外した場合はフォームを無効化する
        if (!isChecked)
        {
            SendMessage(hWndDlg, FWM_DISABLE_FORM, wParam, 0);
            return (INT_PTR)TRUE;
        }

        SendMessage(hWndEdit[sKey], EM_SETREADONLY, FALSE, 0);
        bool isIpCheck = IpKey.end() != std::find(IpKey.begin(), IpKey.end(), sKey);
        if (isIpCheck)
        {
            SendMessage(hWndDlg, FWM_IP_CHECK, wParam, 0);
        }

        bool isPortCheck = PortKey.end() != std::find(PortKey.begin(), PortKey.end(), sKey);
        if (isPortCheck)
        {
            SendMessage(hWndDlg, FWM_PORT_CHECK, wParam, 0);
        }
        return (INT_PTR)TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_ADD:
        {
            int iCurSel = (int)SendMessage(hWndComboAction, CB_GETCURSEL, 0, 0);

            try
            {
                //pFirewall->AddUrlCondition(sUrl.data());
                //pFirewall->AddFilter(iCurSel == 0 ? FW_ACTION_PERMIT : FW_ACTION_BLOCK);
            }
            catch (std::runtime_error& e)
            {
                BOOST_LOG_TRIVIAL(trace) << "CFirewall::AddFilter failed with error: " << e.what();
                MessageBox(hWndDlg, L"フィルターの追加に失敗しました", L"", MB_ICONERROR | MB_OK);
                break;
            }

            std::wstringstream ssListItem;
            //ssListItem << sUrl.data() << L"    " << sProtocol.data() << L"    " << STRING_COMBO[iCurSel];

            //ListBoxの末尾に追加(第3引数に-1を指定)
            SendMessage(hWndList, LB_INSERTSTRING, -1, (LPARAM)ssListItem.str().c_str());

            //SetWindowText(hWndEditAddr, L"");
            //SetWindowText(hWndEditProtocol, L"");
            return (INT_PTR)TRUE;
        }
        case IDC_BUTTON_DEL:
        {
            //未選択の場合は-1が返ってくる
            LRESULT idx = SendMessage(hWndList, LB_GETCURSEL, 0, 0);
            if (idx == -1)
            {
                return (INT_PTR)TRUE;
            }
            int id = MessageBox(hWndDlg, L"削除しますか？", L"", MB_OKCANCEL | MB_ICONEXCLAMATION);

            if (id == IDCANCEL)
            {
                return (INT_PTR)TRUE;
            }

            try
            {
                pFirewall->RemoveFilter(idx);
            }
            catch (std::runtime_error& e)
            {
                BOOST_LOG_TRIVIAL(trace) << "CFirewall::RemovingFilter failed with error: " << e.what();
                MessageBox(hWndDlg, L"フィルターの削除に失敗しました", L"", MB_ICONERROR | MB_OK);
                break;
            }
            SendMessage(hWndList, LB_DELETESTRING, idx, 0);
            return (INT_PTR)TRUE;        
        }
        case IDC_CHECK_ADDR:
        {
            SendMessage(hWndDlg, FWM_CHECKBOX, (WPARAM)"addr", 0);
            return (INT_PTR)TRUE;
        }
        case IDC_CHECK_FQDN:
        {
            SendMessage(hWndDlg, FWM_CHECKBOX, (WPARAM)"fqdn", 0);
            return (INT_PTR)TRUE;
        }
        case IDC_CHECK_PORT:
        {
            SendMessage(hWndDlg, FWM_CHECKBOX, (WPARAM)"port", 0);
            return (INT_PTR)TRUE;
        }
        case IDC_CHECK_PROTOCOL:
        {
            SendMessage(hWndDlg, FWM_CHECKBOX, (WPARAM)"protocol", 0);
            return (INT_PTR)TRUE;
        }
        case IDC_CHECK_URL:
        {
            SendMessage(hWndDlg, FWM_CHECKBOX, (WPARAM)"url", 0);
            return (INT_PTR)TRUE;
        }
        }   //switch (LOWORD(wParam))
        break;
    }
    return (INT_PTR)FALSE;
}