#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace Win32Util 
{
    inline std::string FormatErrorMessage(DWORD error, const std::string& msg)
    {
        static const int BUFFERLENGTH = 1024;
        std::vector<char> buf(BUFFERLENGTH);
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0, error, 0, buf.data(), BUFFERLENGTH - 1, 0);
        return std::string(buf.data()) + "   (" + msg + ")";
    }

    //Win32のエラーコードを例外に変換
    //  クラス利用者はWin32Exceptionをキャッチする
    template <typename T>
    class CWin32Exception : public std::runtime_error
    {
    private:
        T m_dwError;
    public:
        CWin32Exception(T error, const std::string& msg)
            : runtime_error(FormatErrorMessage(error, msg)), m_dwError(error) { }

        T GetErrorCode() const { return m_dwError; }
    };

    inline void ThrowLastError(bool expression, const std::string& msg)
    {
        if (expression) 
        {
            throw CWin32Exception<DWORD>(GetLastError(), msg);
        }
    }

    inline void ThrowHresultError(bool expression, const std::string& msg)
    {
        if (expression)
        {
            throw CWin32Exception<HRESULT>(HRESULT_FROM_WIN32(GetLastError()), msg);
        }
    }

    inline void ThrowWsaError(bool expression, const std::string& msg)
    {
        if (expression)
        {
            throw CWin32Exception<int>(WSAGetLastError(), msg);
        }
    }
}