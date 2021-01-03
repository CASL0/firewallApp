#include "Firewall.h"
#include "Win32Exception.h"
#include <iostream>
#include <iomanip>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/debug_output_backend.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/trivial.hpp>
#include <conio.h>

#pragma comment(lib, "LibFirewall.lib")

using namespace Win32Util;
using namespace ::WfpUtil;
namespace logging = boost::log;
namespace expr = boost::log::expressions;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

int main(void)
{

	try
	{
		CFirewall* firewall = new CFirewall;
		firewall->AddFilter(WFP_ACTION_BLOCK, "IP addr", 0xffffffff, 443);
		_getch();
		firewall->close();
	}
	catch (const CWin32Exception& e)
	{
		std::cout << e.what() << std::endl;
		std::cout << "Error code: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << e.GetErrorCode() << std::endl;

	}
	
}