#pragma once
#include <memory>

namespace Win32Util{ namespace WfpUtil{
	class CFirewall
	{
	private:
		class Impl;
		std::unique_ptr<Impl> pimpl;

	public:
		CFirewall();
		~CFirewall() = default;
		void close();

	};
}}