#pragma once
#include <memory>
#include <string>
#include <Windows.h>

namespace Win32Util{ namespace WfpUtil{

	enum WFP_ACTION
	{
		WFP_ACTION_PERMIT = 0,
		WFP_ACTION_BLOCK,
	};

	class CFirewall
	{
	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;

	public:
		CFirewall();
		~CFirewall() = default;
		void close();
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port);
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, std::string sProtocol);
		void AddFilter(WFP_ACTION action, std::string sAddr, UINT16 port);
		void AddFilter(WFP_ACTION action, std::string sAddr, std::string sProtocol);
		void AddFilter(WFP_ACTION action, std::string sAddr);
		void AddFilter(WFP_ACTION action, UINT16 port);
		void RemoveFilter(WFP_ACTION action, std::string sAddr, UINT32 dwMask, UINT16 port);

	};
}}