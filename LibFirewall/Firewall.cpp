#include <WinSock2.h>
#include <Windows.h>
#include <vector>

#include "Firewall.h"
#include "Win32Exception.h"

#pragma comment(lib, "ws2_32.lib")

namespace Win32Util
{
	typedef struct
	{
		UINT16 port;		//ポート番号
		UINT32 mask;		//サブネットマスク
		UINT32 hexAddr;		//IPアドレス
		UINT64 filterID;	//フィルターID

	} FILTER_COND_INFO;

	class CFirewall::Impl
	{
	public:
		std::vector<FILTER_COND_INFO> m_vecConditions;
		HANDLE m_hEngine;
		GUID m_subLayerGUID;

	public:
		Impl();
		~Impl() = default;
		void close();

	};

	CFirewall::Impl::Impl() : m_hEngine(nullptr), m_subLayerGUID({ 0 })
	{
		DWORD dwRet;
		WSADATA wsaData;
		dwRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
		ThrowWin32Error(dwRet != 0, "WSAStartup failed");

	}

	void CFirewall::Impl::close()
	{
		DWORD dwRet;
		dwRet = WSACleanup();
		ThrowWin32Error(dwRet != 0, "WSACleanup failed");

	}

}	//namespace Win32Util