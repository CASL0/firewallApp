#pragma once
#include <memory>
#include <string>
#include <Windows.h>

namespace Win32Util{ namespace WfpUtil{

	enum FW_ACTION
	{
		FW_ACTION_PERMIT = 0,
		FW_ACTION_BLOCK,
	};

	enum FW_DIRECTION
	{
		FW_DIRECTION_OUTBOUND = 0,
		FW_DIRECTION_INBOUND,
	};

	class CFirewall
	{
	private:
		class Impl;
		std::shared_ptr<Impl> pimpl;

	public:
		CFirewall();
		~CFirewall() = default;
		void close();
		void RemoveFilter(int index);
		void AddIpAddrCondition(const std::string& sIpAddr);
		void AddIpAddrCondition(const std::string& sIpAddr, UINT32 dwMask);
		void AddPortCondition(UINT16 wPort);
		void AddPortCondition(const std::string& sProtocol);
		void AddFqdnCondition(const std::string& sFqdn);
		void AddUrlCondition(const std::string& sUrl);
		void AddProcessCondition(const std::string& sPathToApp);
		void AddServCondition(const std::string& sServName);
		void AddFilter(FW_ACTION action);
		void AllBlock(bool isEnable, FW_DIRECTION direction);
	};
}}