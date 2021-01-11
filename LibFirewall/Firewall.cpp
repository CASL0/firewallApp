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
		std::vector<FILTER_COND_INFO> m_vecConditions;
		HANDLE m_hEngine;
		GUID m_subLayerGUID;

	public:
		Impl();
		~Impl() = default;
		void close();
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port);
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, std::string sProtocol);
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT16 port);
		void AddFilter(WFP_ACTION action, std::string sAddr, std::string sProtocol);
		void AddFilter(WFP_ACTION action, std::string sAddrOrProtocol);		//IPアドレスまたはプロトコルを指定
		void AddFilter(WFP_ACTION action, UINT16 port);
		void RemoveFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port);

		void WfpSetup();
		void AddSubLayer();
		void RemoveSubLayer();
		void RemoveAllFilters();

		//サービス名を解決する
		//存在しなければ0を返す
		UINT16 GetPortByServ(std::string sService);

		//IPアドレスの文字列からホストオーダーへ変換
		//入力例："192.168.0.1"
		UINT32 TranslateStr2Hex(std::string sAddr);

		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT32 dwAddr, UINT32 dwMask);
		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT16 wPort);
	};

	CFirewall::Impl::Impl() : m_hEngine(nullptr), m_subLayerGUID({ 0 })
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

		fwpSubLayer.displayData.name = const_cast<wchar_t*>(L"WfpSublayer");
		fwpSubLayer.displayData.description = const_cast<wchar_t*>(L"create WfpSublayer");
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

	UINT32 CFirewall::Impl::TranslateStr2Hex(std::string sAddr)
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

	//IPアドレス文字列が空文字列の場合はポートのみでフィルター
	//ポートが0の場合はIPアドレスのみでフィルター
	//両方該当する場合はフィルターの追加をしない
	void CFirewall::Impl::AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port)
	{
		BOOST_LOG_TRIVIAL(trace) << "AddFilter begins";

		if (sAddr == "" && port == 0)
		{
			return;
		}

		FWPM_FILTER0 fwpFilter = { 0 };
		std::vector<FWPM_FILTER_CONDITION0> vecFwpConditions;

		fwpFilter.subLayerKey = m_subLayerGUID;
		fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		fwpFilter.weight.type = FWP_EMPTY;
		fwpFilter.displayData.name = const_cast<WCHAR*>(L"IPv4Permit");
		fwpFilter.displayData.description = const_cast<WCHAR*>(L"Filter for IPv4");

		//許可 or 遮断を指定
		fwpFilter.action.type = action == WFP_ACTION_PERMIT ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

		FILTER_COND_INFO filterCondition;

		//IPアドレス文字列が空文字列の場合は、ポートのみをフィルター条件に追加
		if (sAddr != "")
		{
			filterCondition.hexAddr = TranslateStr2Hex(sAddr);
			filterCondition.mask = dwMask;
			SetupConditions(vecFwpConditions, filterCondition.hexAddr, filterCondition.mask);
			BOOST_LOG_TRIVIAL(trace) << "TranslateStr2Hex succeeded";
		}

		//ポートが0の場合は、IPアドレスのみをフィルター条件に追加
		if (port != 0)
		{
			filterCondition.port = port;
			SetupConditions(vecFwpConditions, filterCondition.port);
		}

		fwpFilter.numFilterConditions = vecFwpConditions.size();
		fwpFilter.filterCondition = vecFwpConditions.data();

		BOOST_LOG_TRIVIAL(trace) << "Adding filter";
		DWORD dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterCondition.filterID);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
		m_vecConditions.push_back(filterCondition);
	}

	void CFirewall::Impl::AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, std::string sProtocol)
	{
		UINT16 wPort = GetPortByServ(sProtocol);	
		AddFilter(action, sAddr, dwMask, wPort);
	}

	void CFirewall::Impl::AddFilter(WFP_ACTION action, UINT16 port)
	{
		AddFilter(action, "", 0xffffffff, port);
	}

	void CFirewall::Impl::RemoveAllFilters()
	{
		BOOST_LOG_TRIVIAL(trace) << "RemoveAllFilters begins";
		DWORD dwRet = ERROR_BAD_COMMAND;
		for (auto& elem : m_vecConditions)
		{
			BOOST_LOG_TRIVIAL(trace) << "Removing filter";
			dwRet = FwpmFilterDeleteById0(m_hEngine, elem.filterID);
			ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterDeleteById0 failed");
		}
	}

	void CFirewall::Impl::AddFilter(WFP_ACTION action, std::string sAddr, UINT16 port)
	{
		AddFilter(action, sAddr, 0xffffffff, port);
	}

	void CFirewall::Impl::AddFilter(WFP_ACTION action, std::string sAddr, std::string sProtocol)
	{
		AddFilter(action, sAddr, 0xffffffff, sProtocol);
	}

	void CFirewall::Impl::AddFilter(WFP_ACTION action, std::string sAddrOrProtocol)
	{
		//sAddrOrProtocolをまずはプロトコルとして解釈し、ポートに変換する
		//解決できなければアドレスとして解釈する

		UINT16 wPort = GetPortByServ(sAddrOrProtocol);
		if (wPort == 0)
		{
			AddFilter(action, sAddrOrProtocol, 0xffffffff, 0);
		}
		else
		{
			AddFilter(action, wPort);
		}
	}

	UINT16 CFirewall::Impl::GetPortByServ(std::string sService)
	{
		servent* pServEnt = getservbyname(sService.c_str(), nullptr);
		return pServEnt ? ntohs(pServEnt->s_port):0;
	}

	void CFirewall::Impl::RemoveFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port)
	{
	}
	CFirewall::CFirewall(): pimpl(std::make_shared<Impl>())
	{
	}

	void CFirewall::close()
	{
		pimpl->close();
	}

	void CFirewall::AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port)
	{
		pimpl->AddFilter(action, sAddr, dwMask, port);
	}

	void CFirewall::AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, std::string sProtocol)
	{
		pimpl->AddFilter(action, sAddr, dwMask, sProtocol);
	}

	void CFirewall::AddFilter(WFP_ACTION action, std::string sAddr, UINT16 port)
	{
		pimpl->AddFilter(action, sAddr, port);
	}

	void CFirewall::AddFilter(WFP_ACTION action, std::string sAddr, std::string sProtocol)
	{
		pimpl->AddFilter(action, sAddr, sProtocol);
	}

	void CFirewall::AddFilter(WFP_ACTION action, std::string sAddr)
	{
		pimpl->AddFilter(action, sAddr);
	}

	void CFirewall::AddFilter(WFP_ACTION action, UINT16 port)
	{
		pimpl->AddFilter(action, port);
	}

	void CFirewall::RemoveFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port)
	{
		pimpl->RemoveFilter(action, sAddr, dwMask, port);
	}

}	//namespace WfpUtil
}	//namespace Win32Util