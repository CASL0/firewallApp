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

    //Win32のGetLastError()を例外に変換
    //Win32Exceptionをキャッチする
    class CWin32Exception : public std::runtime_error
    {
    private:
        DWORD m_dwError;
    public:
        CWin32Exception(DWORD error, const std::string& msg)
            : runtime_error(FormatErrorMessage(error, msg)), m_dwError(error) { }

        DWORD GetErrorCode() const { return m_dwError; }
    };

    inline void ThrowWin32Error(bool expression, const std::string& msg)
    {
        if (expression) 
        {
            throw CWin32Exception(GetLastError(), msg);
        }
    }
}