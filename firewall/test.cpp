#include "Firewall.h"
#include "Win32Exception.h"
#include <iostream>
#include <iomanip>

#pragma comment(lib, "LibFirewall.lib")

using namespace Win32Util;

int main(void)
{
	try
	{
		CFirewall firewall;
		firewall.close();
	}
	catch (const CWin32Exception& e)
	{
		std::cout << e.what() << std::endl;
		std::cout << "Error code: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << e.GetErrorCode() << std::endl;

	}
	
}