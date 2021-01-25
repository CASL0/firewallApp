#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <vector>
#include <fwpmu.h>
#include <memory>
#include <boost/log/trivial.hpp>

#include "Firewall.h"
#include "Win32Exception.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Win32Util{ namespace WfpUtil{
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
		HANDLE m_hEngine;
		GUID m_subLayerGUID;
		std::vector<UINT64> m_vecFilterId;
		std::vector<FWPM_FILTER_CONDITION0> m_vecConditions;
	public:
		Impl();
		~Impl() = default;
		void close();

		void AddIpAddrCondition(const std::string& sIpAddr);
		void AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask);
		void AddPortCondition(UINT16 wPort);
		void AddPortCondition(const std::string& sProtocol);

		void AddFilter(FW_ACTION action);
		
		//フィルターの項番を指定して削除する
		//何番目に追加したかを指定する(0-based)
		//例：RemoveFilter(2) -> ３番目に追加したフィルターを削除する
		void RemoveFilter(int index);

		void WfpSetup();
		void AddSubLayer();
		void RemoveSubLayer();
		void RemoveAllFilters();

		//サービス名を解決する(etc/servicesからの解決)
		//存在しない場合runtime_errorをthrowする(クライアントコードでは例外を捕捉する)
		UINT16 GetPortByServ(const std::string& sService);

		//IPアドレスの文字列からホストオーダーへ変換
		//入力例："192.168.0.1"
		UINT32 TranslateStr2Hex(const std::string& sAddr);

		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT32 dwAddr, UINT32 dwMask);
		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT16 wPort);
	};

	CFirewall::Impl::Impl() :
		m_hEngine(nullptr),
		m_subLayerGUID({ 0 }),
		m_vecFilterId(std::vector<UINT64>()), 
		m_vecConditions(std::vector<FWPM_FILTER_CONDITION0>())
	{
		DWORD dwRet;
		WSADATA wsaData;
		dwRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
		ThrowWsaError(dwRet != 0, "WSAStartup failed");
		WfpSetup();
	}

	void CFirewall::Impl::close()
	{
		RemoveAllFilters();

		DWORD dwRet;
		dwRet = WSACleanup();
		ThrowWsaError(dwRet != 0, "WSACleanup failed");

		RemoveSubLayer();
		dwRet = FwpmEngineClose0(m_hEngine);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmEngineClose0 failed");
	}

	void CFirewall::Impl::WfpSetup()
	{
		BOOST_LOG_TRIVIAL(trace) << "WfpSetup begins";
		DWORD dwRet;
		dwRet = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &m_hEngine);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmEngineOpen0 failed");
		AddSubLayer();
	}

	void CFirewall::Impl::AddSubLayer()
	{
		BOOST_LOG_TRIVIAL(trace) << "AddSubLayer begins";
		FWPM_SUBLAYER0 fwpSubLayer = { 0 };
		RPC_STATUS rpcStatus = RPC_S_OK;

		rpcStatus = UuidCreate(&fwpSubLayer.subLayerKey);
		ThrowLastError(rpcStatus != RPC_S_OK, "UuidCreate failed");
		CopyMemory(&m_subLayerGUID, &fwpSubLayer.subLayerKey, sizeof(fwpSubLayer.subLayerKey));
		BOOST_LOG_TRIVIAL(trace) << "UuidCreate succeeded";

		fwpSubLayer.displayData.name = const_cast<WCHAR*>(L"WfpSublayer");
		fwpSubLayer.displayData.description = const_cast<WCHAR*>(L"create WfpSublayer");
		fwpSubLayer.flags = 0;
		fwpSubLayer.weight = 0x100;

		BOOST_LOG_TRIVIAL(trace) << "Adding Sublayer";
		DWORD dwRet = FwpmSubLayerAdd0(m_hEngine, &fwpSubLayer, nullptr);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmSubLayerAdd0 failed");
	}

	void CFirewall::Impl::RemoveSubLayer()
	{
		BOOST_LOG_TRIVIAL(trace) << "Removing Sublayer";
		DWORD dwRet = FwpmSubLayerDeleteByKey0(m_hEngine, &m_subLayerGUID);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmSubLayerDeleteByKey0 failed");
		ZeroMemory(&m_subLayerGUID, sizeof(GUID));
	}

	UINT32 CFirewall::Impl::TranslateStr2Hex(const std::string& sAddr)
	{
		in_addr hexAddr;
		int iRet = inet_pton(AF_INET, sAddr.c_str(), &hexAddr);
		ThrowWsaError(iRet != 1, "inet_pton failed");
		return ntohl(hexAddr.S_un.S_addr);
	}

	inline void CFirewall::Impl::SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT32 dwAddr, UINT32 dwMask)
	{
		std::shared_ptr<FWP_V4_ADDR_AND_MASK> pFwpAddrMask = std::make_shared<FWP_V4_ADDR_AND_MASK>();
		pFwpAddrMask->addr = dwAddr;
		pFwpAddrMask->mask = dwMask;

		FWPM_FILTER_CONDITION0 fwpCondition = { 0 };
		fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		fwpCondition.matchType = FWP_MATCH_EQUAL;
		fwpCondition.conditionValue.type = FWP_V4_ADDR_MASK;
		fwpCondition.conditionValue.v4AddrMask = pFwpAddrMask.get();
		vecFwpConditions.push_back(fwpCondition);
	}

	inline void CFirewall::Impl::SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT16 wPort)
	{
		FWPM_FILTER_CONDITION0 fwpCondition = { 0 };
		fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		fwpCondition.matchType = FWP_MATCH_EQUAL;
		fwpCondition.conditionValue.type = FWP_UINT16;
		fwpCondition.conditionValue.uint16 = wPort;
		vecFwpConditions.push_back(fwpCondition);
	}

	void CFirewall::Impl::RemoveAllFilters()
	{
		BOOST_LOG_TRIVIAL(trace) << "RemoveAllFilters begins";
		DWORD dwRet = ERROR_BAD_COMMAND;
		for (auto& elem : m_vecFilterId)
		{
			BOOST_LOG_TRIVIAL(trace) << "Removing filter";
			dwRet = FwpmFilterDeleteById0(m_hEngine, elem);
			ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterDeleteById0 failed");
		}
	}

	UINT16 CFirewall::Impl::GetPortByServ(const std::string& sService)
	{
		servent* pServEnt = getservbyname(sService.c_str(), nullptr);
		if (pServEnt == nullptr)
		{
			throw std::runtime_error("protocol not found");
		}
		return ntohs(pServEnt->s_port);
	}

	void CFirewall::Impl::RemoveFilter(int index)
	{
		BOOST_LOG_TRIVIAL(trace) << "RemoveFilter begins";
		DWORD dwRet = ERROR_BAD_COMMAND;

		BOOST_LOG_TRIVIAL(trace) << "Removing filter";
		dwRet = FwpmFilterDeleteById0(m_hEngine, m_vecFilterId.at(index));
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterDeleteById0 failed");
		m_vecFilterId.erase(m_vecFilterId.cbegin() + index);
	}

	void CFirewall::Impl::AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask)
	{
		UINT32 hexAddr = TranslateStr2Hex(sIpAddr);
		SetupConditions(m_vecConditions, hexAddr, dwMask);
		BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << sIpAddr;
	}

	void CFirewall::Impl::AddIpAddrCondition(const std::string& sIpAddr)
	{
		AddIpAddrCondition(sIpAddr, 0xffffffff);
	}

	void CFirewall::Impl::AddPortCondition(UINT16 wPort)
	{
		SetupConditions(m_vecConditions, wPort);
		BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << wPort;
	}

	void CFirewall::Impl::AddPortCondition(const std::string& sProtocol)
	{
		UINT16 wPort = GetPortByServ(sProtocol);
		AddPortCondition(wPort);
	}

	void CFirewall::Impl::AddFilter(FW_ACTION action)
	{
		BOOST_LOG_TRIVIAL(trace) << "AddFilter begins";
		FWPM_FILTER0 fwpFilter = { 0 };
		fwpFilter.subLayerKey = m_subLayerGUID;
		fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

		fwpFilter.weight.type = FWP_EMPTY;

		fwpFilter.displayData.name = const_cast<WCHAR*>(L"IPv4Permit");
		fwpFilter.displayData.description = const_cast<WCHAR*>(L"Filter for IPv4");

		fwpFilter.action.type = action == FW_ACTION_PERMIT ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

		fwpFilter.numFilterConditions = m_vecConditions.size();
		fwpFilter.filterCondition = m_vecConditions.data();

		BOOST_LOG_TRIVIAL(trace) << "Adding filter";
		UINT64 filterId = 0;
		DWORD dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterId);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
		m_vecFilterId.push_back(filterId);
		m_vecConditions.clear();
	}

	CFirewall::CFirewall(): pimpl(std::make_shared<Impl>())
	{
	}

	void CFirewall::close()
	{
		pimpl->close();
	}

	void CFirewall::RemoveFilter(int index)
	{
		pimpl->RemoveFilter(index);
	}

	void CFirewall::AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask)
	{
		pimpl->AddIpAddrCondition(sIpAddr, dwMask);
	}

	void CFirewall::AddIpAddrCondition(const std::string& sIpAddr)
	{
		pimpl->AddIpAddrCondition(sIpAddr);
	}

	void CFirewall::AddPortCondition(UINT16 wPort)
	{
		pimpl->AddPortCondition(wPort);
	}

	void CFirewall::AddPortCondition(const std::string& sProtocol)
	{
		pimpl->AddPortCondition(sProtocol);
	}

	void CFirewall::AddFilter(FW_ACTION action)
	{
		pimpl->AddFilter(action);
	}

}	//namespace WfpUtil
}	//namespace Win32Util