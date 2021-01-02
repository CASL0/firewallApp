#include <WinSock2.h>
#include <Windows.h>
#include <vector>
#include <fwpmu.h>
#include <boost/log/trivial.hpp>

#include "Firewall.h"
#include "Win32Exception.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
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

		void WfpSetup();
		void AddSubLayer();
		void RemoveSubLayer();
	};

	CFirewall::Impl::Impl() : m_hEngine(nullptr), m_subLayerGUID({ 0 })
	{
		DWORD dwRet;
		WSADATA wsaData;
		dwRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
		ThrowWin32Error(dwRet != 0, "WSAStartup failed");
		WfpSetup();
	}

	void CFirewall::Impl::close()
	{
		DWORD dwRet;
		dwRet = WSACleanup();
		ThrowWin32Error(dwRet != 0, "WSACleanup failed");

		RemoveSubLayer();
		dwRet = FwpmEngineClose0(m_hEngine);
		ThrowWin32Error(dwRet != ERROR_SUCCESS, "FwpmEngineClose0 failed");
	}

	void CFirewall::Impl::WfpSetup()
	{
		BOOST_LOG_TRIVIAL(trace) << "WfpSetup begins";
		DWORD dwRet;
		dwRet = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &m_hEngine);
		ThrowWin32Error(dwRet != ERROR_SUCCESS, "FwpmEngineOpen0 failed");
		AddSubLayer();
	}
	
	void CFirewall::Impl::AddSubLayer()
	{
		BOOST_LOG_TRIVIAL(trace) << "AddSubLayer begins";
		FWPM_SUBLAYER0 fwpSubLayer = { 0 };
		RPC_STATUS rpcStatus = RPC_S_OK;

		rpcStatus = UuidCreate(&fwpSubLayer.subLayerKey);
		ThrowWin32Error(rpcStatus != RPC_S_OK, "UuidCreate failed");
		CopyMemory(&m_subLayerGUID, &fwpSubLayer.subLayerKey, sizeof(fwpSubLayer.subLayerKey));
		BOOST_LOG_TRIVIAL(trace) << "UuidCreate succeeded";

		fwpSubLayer.displayData.name = const_cast<wchar_t*>(L"WfpSublayer");
		fwpSubLayer.displayData.description = const_cast<wchar_t*>(L"create WfpSublayer");
		fwpSubLayer.flags = 0;
		fwpSubLayer.weight = 0x100;

		BOOST_LOG_TRIVIAL(trace) << "Adding Sublayer";
		DWORD dwRet = FwpmSubLayerAdd0(m_hEngine, &fwpSubLayer, nullptr);
		ThrowWin32Error(dwRet != ERROR_SUCCESS, "FwpmSubLayerAdd0 failed");
	}

	void CFirewall::Impl::RemoveSubLayer()
	{
		BOOST_LOG_TRIVIAL(trace) << "Removing Sublayer";
		DWORD dwRet = FwpmSubLayerDeleteByKey0(m_hEngine, &m_subLayerGUID);
		ThrowWin32Error(dwRet != ERROR_SUCCESS, "FwpmSubLayerDeleteByKey0");
		ZeroMemory(&m_subLayerGUID, sizeof(GUID));
	}
	
	CFirewall::CFirewall(): pimpl(std::make_unique<Impl>())
	{
	}

	void CFirewall::close()
	{
		pimpl->close();
	}
}	//namespace Win32Util