#pragma once

namespace Win32Util 
{
	class CFirewall
	{
	private:
		class Impl;
		Impl* pimpl;
	public:
		CFirewall();
		~CFirewall() = default;
		void close();
	};
}