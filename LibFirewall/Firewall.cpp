#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <WinInet.h>
#include <vector>
#include <fwpmu.h>
#include <memory>
#include <array>
#include <iphlpapi.h>
#include <boost/log/trivial.hpp>

#include "Firewall.h"
#include "Win32Exception.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Iphlpapi.lib")

#pragma warning(disable : 4996)

namespace Win32Util{ namespace WfpUtil{

	typedef struct
	{
		UINT64 v4;
		UINT64 v6;
	} FILTER_ID;

	typedef struct _IP_ADDR
	{
		int af;
		union
		{
			UINT32 v4;
			std::array<BYTE, 16> v6;
		};
	} IP_ADDR;

	class CFirewall::Impl
	{
	public:
		//フィルター条件に追加する場合、該当するフラグを立てる
		//IPアドレス --> 1bit目を立てる
		//ポート番号 --> 2bit目を立てる
		//プロセス	 --> 3bit目を立てる
		enum
		{
			FLAG_IP_ADDR_COND = 0x01,
			FLAG_PORT_COND	  = 0x02,
			FLAG_PROCESS_COND = 0x04,

		};

		LPCWSTR FW_APP_NAME = L"WFP_Utility";
		using FILTER_ID_STORE = std::vector<std::vector<UINT64>>;
	public:
		HANDLE m_hEngine;
		GUID m_subLayerGUID;
		FILTER_ID_STORE m_filterIdStore;
		std::vector<IP_ADDR> m_vecIpAddr;
		UINT16 m_wPort;
		std::string m_sPathToApp;
		BYTE m_flagConditions;
		std::vector<UINT64> m_vecAllBlockFilterIDs;
		int m_numDnsServers;	//削除する時、フィルターIDのオフセットになる

	public:
		Impl();
		~Impl() = default;
		void close();

		void AddIpAddrCondition(const std::string& sIpAddr);
		void AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask);
		void AddPortCondition(UINT16 wPort);
		void AddPortCondition(const std::string& sProtocol);
		void AddFqdnCondition(const std::string& sFqdn);
		void AddUrlCondition(const std::string& sUrl);
		void AddProcessCondition(const std::string& sPathToApp);
		void AddFilter(FW_ACTION action);
		void AllBlock(bool isEnable, FW_DIRECTION direction);

		//フィルターの項番を指定して削除する
		//何番目に追加したかを指定する(0-based)
		//例：RemoveFilter(2) -> ３番目に追加したフィルターを削除する
		void RemoveFilter(int index);

		void WfpSetup();
		void AddSubLayer();
		void RemoveSubLayer();
		void RemoveAllFilters();

		//[in] sUrl: URL
		//[out] sFqdn: FQDN, sProtocol: プロトコル
		//パースに失敗した場合Win32Exceptionをthrowする(クライアントコードでは例外を捕捉する)
		void ParseUrl(const std::string& sUrl, std::string& sFqdn, std::string& sProtocol);

		//ホスト名を解決する
		//存在しない場合Win32Exceptionをthrowする(クライアントコードでは例外を捕捉する)
		void FqdnToIpAddr(const std::string& sFqdn);

		//サービス名を解決する(etc/servicesからの解決)
		//存在しない場合runtime_errorをthrowする(クライアントコードでは例外を捕捉する)
		UINT16 GetPortByServ(const std::string& sService);

		//IPアドレスの文字列からホストオーダーへ変換
		//入力例："192.168.0.1"
		UINT32 TranslateStr2Hex(const std::string& sAddr);

		std::vector<std::string> GetDnsServers();

		std::wstring AstrToWstr(const std::string& src);

		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, const std::array<BYTE, 16> pByV6Addr, UINT8 prefixLength);
		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT32 dwAddr, UINT32 dwMask);
		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, UINT16 wPort);
		inline void SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, const std::string& sPathToApp);

		inline void InitCondFlags();
	};

	CFirewall::Impl::Impl() :
		m_hEngine(nullptr),
		m_subLayerGUID({ 0 }),
		m_filterIdStore(FILTER_ID_STORE()),
		m_vecIpAddr(std::vector<IP_ADDR>()),
		m_wPort(0),
		m_sPathToApp(std::string()),
		m_flagConditions(0),
		m_vecAllBlockFilterIDs(std::vector<UINT64>()),
		m_numDnsServers(0)

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

		//DNSサーバーとの通信は許可する
		auto dnsServerList = GetDnsServers();
		for (const auto& elem : dnsServerList)
		{
			AddIpAddrCondition(elem);
		}

		AddFilter(FW_ACTION_PERMIT);
		m_numDnsServers = dnsServerList.size();
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

		fwpSubLayer.displayData.name = const_cast<WCHAR*>(FW_APP_NAME);
		fwpSubLayer.displayData.description = const_cast<WCHAR*>(FW_APP_NAME);
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

	std::vector<std::string> CFirewall::Impl::GetDnsServers()
	{
		ULONG ulOutBufLen = sizeof(FIXED_INFO);
		GetNetworkParams(nullptr, &ulOutBufLen);
		std::shared_ptr<FIXED_INFO> pFixedInfo(
			(FIXED_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulOutBufLen), 
			[](FIXED_INFO* lpMem) 
			{
				HeapFree(GetProcessHeap(), 0, lpMem);
			}
		);
		DWORD dwRet = GetNetworkParams(pFixedInfo.get(), &ulOutBufLen);
		ThrowLastError(dwRet != ERROR_SUCCESS, "GetNetworkParams failed");
		
		std::vector<std::string> vecDnsServers;
		vecDnsServers.push_back(pFixedInfo->DnsServerList.IpAddress.String);
		BOOST_LOG_TRIVIAL(trace) << "DNS server: " << pFixedInfo->DnsServerList.IpAddress.String;

		auto pIpAddr = pFixedInfo->DnsServerList.Next;
		while (pIpAddr)
		{
			vecDnsServers.push_back(pIpAddr->IpAddress.String);
			BOOST_LOG_TRIVIAL(trace) << "DNS server: " << pIpAddr->IpAddress.String;
			pIpAddr = pIpAddr->Next;
		}

		return vecDnsServers;
	}

	inline void CFirewall::Impl::SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, const std::array<BYTE, 16> pByV6Addr, UINT8 prefixLength)
	{
		std::shared_ptr<FWP_V6_ADDR_AND_MASK> pFwpV6AddrMask = std::make_shared<FWP_V6_ADDR_AND_MASK>();
		CopyMemory(pFwpV6AddrMask->addr, pByV6Addr.data(), 16);
		pFwpV6AddrMask->prefixLength = prefixLength;

		FWPM_FILTER_CONDITION0 fwpCondition = { 0 };
		fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		fwpCondition.matchType = FWP_MATCH_EQUAL;
		fwpCondition.conditionValue.type = FWP_V6_ADDR_MASK;
		fwpCondition.conditionValue.v6AddrMask = pFwpV6AddrMask.get();
		vecFwpConditions.push_back(fwpCondition);
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

	inline void CFirewall::Impl::SetupConditions(std::vector<FWPM_FILTER_CONDITION0>& vecFwpConditions, const std::string& sPathToApp)
	{
		FWP_BYTE_BLOB* appBlob = nullptr;
		DWORD dwRet = FwpmGetAppIdFromFileName0(AstrToWstr(sPathToApp).c_str(), &appBlob);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmGetAppIdFromFileName0 failed");
		FWPM_FILTER_CONDITION0 fwpCondition = { 0 };
		fwpCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
		fwpCondition.matchType = FWP_MATCH_EQUAL;
		fwpCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
		fwpCondition.conditionValue.byteBlob = appBlob;
		vecFwpConditions.push_back(fwpCondition);
	}

	inline void CFirewall::Impl::InitCondFlags()
	{
		m_vecIpAddr.clear();
		m_flagConditions = 0;
	}

	std::wstring CFirewall::Impl::AstrToWstr(const std::string& src)
	{
		auto destSize = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src.c_str(), -1, nullptr, 0);
		std::vector<WCHAR> dest(destSize);
		destSize = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src.c_str(), -1, dest.data(), dest.size());
		ThrowLastError(destSize == 0, "MultiByteToWideChar failed");
		dest.resize(destSize);
		return std::wstring(dest.begin(), dest.end());
	}

	void CFirewall::Impl::RemoveAllFilters()
	{
		BOOST_LOG_TRIVIAL(trace) << "RemoveAllFilters begins";
		DWORD dwRet = ERROR_BAD_COMMAND;
		for (const auto& vecElem : m_filterIdStore)
		{
			for (const auto& u64Elem : vecElem)
			{
				BOOST_LOG_TRIVIAL(trace) << "Removing a filter: " << u64Elem;
				dwRet = FwpmFilterDeleteById0(m_hEngine, u64Elem);
				ThrowHresultError(dwRet != ERROR_SUCCESS && dwRet != FWP_E_FILTER_NOT_FOUND, "FwpmFilterDeleteById0 failed");
			}
		}

		for (const auto& elem : m_vecAllBlockFilterIDs)
		{
			BOOST_LOG_TRIVIAL(trace) << "Removing a filter: " << elem;
			dwRet = FwpmFilterDeleteById0(m_hEngine, elem);
			ThrowHresultError(dwRet != ERROR_SUCCESS && dwRet != FWP_E_FILTER_NOT_FOUND, "FwpmFilterDeleteById0 failed");
		}
	}

	void CFirewall::Impl::ParseUrl(const std::string& sUrl, std::string& sFqdn, std::string& sProtocol)
	{
		BOOST_LOG_TRIVIAL(trace) << "URL: " << sUrl;
		URL_COMPONENTSA urlComponents = { 0 };

		static const int URL_BUFFER_SIZE = 1024;
		std::vector<CHAR> host(URL_BUFFER_SIZE);
		std::vector<CHAR> scheme(URL_BUFFER_SIZE);

		urlComponents.dwStructSize     = sizeof(URL_COMPONENTSA);
		urlComponents.lpszHostName     = host.data();
		urlComponents.lpszScheme       = scheme.data();
		urlComponents.dwHostNameLength = URL_BUFFER_SIZE;
		urlComponents.dwSchemeLength   = URL_BUFFER_SIZE;

		bool bRet = InternetCrackUrlA(sUrl.c_str(), sUrl.length(), 0, &urlComponents);
		ThrowLastError(bRet == false, "InternetCrackUrl failed");

		BOOST_LOG_TRIVIAL(trace) << "InternetCrackUrl succeeded";
		host.resize(urlComponents.dwHostNameLength);
		scheme.resize(urlComponents.dwSchemeLength);

		sFqdn     = std::string(host.begin(), host.end());
		sProtocol = std::string(scheme.begin(), scheme.end());
	}

	void CFirewall::Impl::FqdnToIpAddr(const std::string& sFqdn)
	{
		BOOST_LOG_TRIVIAL(trace) << "FQDN: " << sFqdn;
		addrinfo hints = { 0 };
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_ALL;

		addrinfo* pAddrInfo = nullptr;
		int iRet = getaddrinfo(sFqdn.c_str(), nullptr, &hints, &pAddrInfo);
		ThrowWsaError(iRet != 0, "getaddrinfo failed");

		BOOST_LOG_TRIVIAL(trace) << "getaddrinfo succeeded";

		SOCKADDR_IN*  sockAddrV4 = nullptr;
		SOCKADDR_IN6* sockAddrV6 = nullptr;
		for (ADDRINFO* ptr = pAddrInfo; ptr != nullptr; ptr = ptr->ai_next)
		{
			IP_ADDR ipAddr = { 0 };
			switch (ptr->ai_family)
			{
			case AF_INET:
			{
				sockAddrV4 = (SOCKADDR_IN*)ptr->ai_addr;
				ipAddr.af = AF_INET;
				ipAddr.v4 = ntohl(sockAddrV4->sin_addr.S_un.S_addr);
				BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << inet_ntoa(sockAddrV4->sin_addr);
				break;
			}
			case AF_INET6:
			{
				sockAddrV6 = (SOCKADDR_IN6*)ptr->ai_addr;
				ipAddr.af = AF_INET6;
				CopyMemory(ipAddr.v6.data(), sockAddrV6->sin6_addr.u.Byte, 16);
				std::vector<CHAR> ipBuffer(50);
				BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << inet_ntop(AF_INET6, &sockAddrV6->sin6_addr, ipBuffer.data(), 50);
				break;
			}
			default:
				continue;
			}
			m_vecIpAddr.push_back(ipAddr);
		}

		freeaddrinfo(pAddrInfo);
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

		for (const auto& elem : m_filterIdStore.at(index + m_numDnsServers))
		{
			BOOST_LOG_TRIVIAL(trace) << "Removing a filter: " << elem;
			dwRet = FwpmFilterDeleteById0(m_hEngine, elem);
			ThrowHresultError(dwRet != ERROR_SUCCESS && dwRet != FWP_E_FILTER_NOT_FOUND, "FwpmFilterDeleteById0 failed");
		}
		m_filterIdStore.erase(m_filterIdStore.cbegin() + index + m_numDnsServers);
	}

	void CFirewall::Impl::AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask)
	{
		UINT32 hexAddr = TranslateStr2Hex(sIpAddr);
		IP_ADDR ipAddr = { 0 };
		ipAddr.af = AF_INET;
		ipAddr.v4 = hexAddr;
		m_vecIpAddr.push_back(ipAddr);
		m_flagConditions |= FLAG_IP_ADDR_COND;
		BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << sIpAddr;
	}

	void CFirewall::Impl::AddIpAddrCondition(const std::string& sIpAddr)
	{
		AddIpAddrCondition(sIpAddr, 0xffffffff);
	}

	void CFirewall::Impl::AddPortCondition(UINT16 wPort)
	{
		m_wPort = wPort;
		m_flagConditions |= FLAG_PORT_COND;
		BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << wPort;
	}

	void CFirewall::Impl::AddPortCondition(const std::string& sProtocol)
	{
		UINT16 wPort = GetPortByServ(sProtocol);
		AddPortCondition(wPort);
	}

	void CFirewall::Impl::AddFqdnCondition(const std::string& sFqdn)
	{
		FqdnToIpAddr(sFqdn);
		m_flagConditions |= FLAG_IP_ADDR_COND;
	}

	void CFirewall::Impl::AddUrlCondition(const std::string& sUrl)
	{
		std::string sFqdn;
		std::string sProtocol;
		ParseUrl(sUrl, sFqdn, sProtocol);

		AddFqdnCondition(sFqdn);
		AddPortCondition(sProtocol);
	}

	void CFirewall::Impl::AddProcessCondition(const std::string& sPathToApp)
	{
		m_sPathToApp = sPathToApp;
		m_flagConditions |= FLAG_PROCESS_COND;
		BOOST_LOG_TRIVIAL(trace) << "Adding a condition: " << sPathToApp;
	}

	void CFirewall::Impl::AddFilter(FW_ACTION action)
	{
		BOOST_LOG_TRIVIAL(trace) << "AddFilter begins";
		FWPM_FILTER0 fwpFilter = { 0 };
		fwpFilter.subLayerKey = m_subLayerGUID;

		//許可の方を優先する
		fwpFilter.weight.type = FWP_UINT8;
		fwpFilter.weight.uint8 = action == FW_ACTION_PERMIT ? 2 : 1;

		fwpFilter.displayData.name = const_cast<WCHAR*>(FW_APP_NAME);
		fwpFilter.displayData.description = const_cast<WCHAR*>(FW_APP_NAME);

		fwpFilter.action.type = action == FW_ACTION_PERMIT ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

		UINT64 filterID;
		std::vector<UINT64> vecFilterID;

		std::vector<FWPM_FILTER_CONDITION0> vecWfpConditions;
		if (m_flagConditions & FLAG_PROCESS_COND)
		{
			SetupConditions(vecWfpConditions, m_sPathToApp);
		}

		if (m_flagConditions & FLAG_PORT_COND)
		{
			SetupConditions(vecWfpConditions, m_wPort);
		}

		//IPアドレスを指定しない場合、このままフィルターを追加する
		if ((m_flagConditions & FLAG_IP_ADDR_COND) == 0)
		{
			fwpFilter.numFilterConditions = vecWfpConditions.size();
			fwpFilter.filterCondition = vecWfpConditions.data();
			//v4用のフィルターを追加
			fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
			DWORD dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterID);
			ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
			BOOST_LOG_TRIVIAL(trace) << "Adding a filter for IPv4: " << filterID;
			vecFilterID.push_back(filterID);

			//v6用のフィルターを追加
			fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
			dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterID);
			ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
			BOOST_LOG_TRIVIAL(trace) << "Adding a filter for IPv6: " << filterID;
			vecFilterID.push_back(filterID);
			m_filterIdStore.push_back(vecFilterID);
			InitCondFlags();
			return;
		}

		for (const auto& elem : m_vecIpAddr)
		{

			if (elem.af == AF_INET)
			{
				SetupConditions(vecWfpConditions, elem.v4, 0xffffffff);
				fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
				BOOST_LOG_TRIVIAL(trace) << "Adding a filter for IPv4";
			}
			else if (elem.af == AF_INET6)
			{
				SetupConditions(vecWfpConditions, elem.v6, 128);
				fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
				BOOST_LOG_TRIVIAL(trace) << "Adding a filter for IPv6";
			}

			fwpFilter.numFilterConditions = vecWfpConditions.size();
			fwpFilter.filterCondition = vecWfpConditions.data();
			
			DWORD dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterID);
			ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
			BOOST_LOG_TRIVIAL(trace) << filterID;
			vecFilterID.push_back(filterID);

			vecWfpConditions.pop_back();
		}
		m_filterIdStore.push_back(vecFilterID);
		InitCondFlags();
	}

	void CFirewall::Impl::AllBlock(bool isEnable, FW_DIRECTION direction)
	{
		//isEnable == false ---> 全遮断を無効化する
		if (!isEnable)
		{
			for (const auto& elem : m_vecAllBlockFilterIDs)
			{
				BOOST_LOG_TRIVIAL(trace) << "Removing a filter: " << elem;
				DWORD dwRet = FwpmFilterDeleteById0(m_hEngine, elem);
				ThrowHresultError(dwRet != ERROR_SUCCESS && dwRet != FWP_E_FILTER_NOT_FOUND, "FwpmFilterDeleteById0 failed");
			}
			m_vecAllBlockFilterIDs.clear();
			return;
		}

		FWPM_FILTER0 fwpFilter = { 0 };
		UINT64 filterID;
		fwpFilter.subLayerKey = m_subLayerGUID;

		fwpFilter.weight.type = FWP_UINT8;
		fwpFilter.weight.uint8 = 1;
		fwpFilter.displayData.name = const_cast<WCHAR*>(FW_APP_NAME);
		fwpFilter.displayData.description = const_cast<WCHAR*>(FW_APP_NAME);
		fwpFilter.action.type = FWP_ACTION_BLOCK;

		//全アプリの通信を対象とする
		fwpFilter.numFilterConditions = 0;

		fwpFilter.layerKey = direction == FW_DIRECTION_OUTBOUND ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
		DWORD dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterID);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
		BOOST_LOG_TRIVIAL(trace) << "All block IPv4: " << filterID;
		m_vecAllBlockFilterIDs.push_back(filterID);
		
		fwpFilter.layerKey = direction == FW_DIRECTION_OUTBOUND ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
		dwRet = FwpmFilterAdd0(m_hEngine, &fwpFilter, nullptr, &filterID);
		ThrowHresultError(dwRet != ERROR_SUCCESS, "FwpmFilterAdd0 failed");
		BOOST_LOG_TRIVIAL(trace) << "All block IPv6: " << filterID;
		m_vecAllBlockFilterIDs.push_back(filterID);
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

	void CFirewall::AddFqdnCondition(const std::string& sFqdn)
	{
		pimpl->AddFqdnCondition(sFqdn);
	}

	void CFirewall::AddUrlCondition(const std::string& sUrl)
	{
		pimpl->AddUrlCondition(sUrl);
	}

	void CFirewall::AddProcessCondition(const std::string& sPathToApp)
	{
		pimpl->AddProcessCondition(sPathToApp);
	}

	void CFirewall::AddFilter(FW_ACTION action)
	{
		pimpl->AddFilter(action);
	}

	void CFirewall::AllBlock(bool isEnable, FW_DIRECTION direction)
	{
		pimpl->AllBlock(isEnable, direction);
	}

}	//namespace WfpUtil
}	//namespace Win32Util