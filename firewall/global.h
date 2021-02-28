#pragma once
#include <tchar.h>
#include <string>
#include <map>
#include <array>
#include <vector>
#include <utility>
#include <Windows.h>
#include "resource.h"

#define FWM_DISABLE_FORM (WM_APP + 1)
#define FWM_CHECKBOX     (FWM_DISABLE_FORM + 1)
#define FWM_IP_CHECK     (FWM_CHECKBOX + 1)
#define FWM_PORT_CHECK   (FWM_IP_CHECK + 1)

using tstring = std::basic_string<TCHAR>;
std::map<UINT, tstring> stringMap;


tstring StrResourceFromStringTable(UINT dwResourceID);
void BuildStringMap();



//ctrlのID ---> StringTableのID
const std::map<UINT, UINT> ctrlToLabel =
{
	{IDC_BUTTON_ADD		,IDS_BTN_LABEL_ADD},
	{IDC_BUTTON_DEL		,IDS_BTN_LABEL_DEL},
	{IDC_BUTTON_ALLBLOCK,IDS_BTN_LABEL_ALLBLOCK_ENABLE},
	{IDC_CHECK_ADDR		,IDS_STATIC_TEXT_IPADDR},
	{IDC_CHECK_PORT		,IDS_STATIC_TEXT_PORT},
	{IDC_CHECK_FQDN		,IDS_STATIC_TEXT_FQDN},
	{IDC_CHECK_PROTOCOL ,IDS_STATIC_TEXT_PROTOCOL},
	{IDC_CHECK_URL		,IDS_STATIC_TEXT_URL},
	{IDC_CHECK_PROCESS	,IDS_STATIC_TEXT_PROCESS},
	{IDC_TEXT_ACTION	,IDS_STATIC_TEXT_ACTION},
	{IDC_TEXT_ALLBLOCK  ,IDS_STATIC_TEXT_ALLBLOCK_ENABLE},
	{IDC_CHECK_SERV		,IDS_STATIC_TEXT_SERV},	
};

//チェックボックスのID ---> editテキストのID
const std::map<UINT, UINT> chkIDToEditID =
{
	{IDC_CHECK_ADDR    ,IDC_IPADDRESS},
	{IDC_CHECK_PORT    ,IDC_EDIT_PORT},
	{IDC_CHECK_FQDN    ,IDC_EDIT_FQDN},
	{IDC_CHECK_PROTOCOL,IDC_EDIT_PROTOCOL},
	{IDC_CHECK_URL     ,IDC_EDIT_URL},
	{IDC_CHECK_PROCESS ,IDC_EDIT_PROCESS},
	{IDC_CHECK_SERV	   ,IDC_EDIT_SERV},
};

//StringTableのID
const std::array<UINT, 21> stringTableIDs =
{
	IDS_APP_TITLE,
	IDS_ERROR_FW_INIT,
	IDS_ERROR_FW_ADD_FILTER,
	IDS_ERROR_FW_RM_FILTER,
	IDS_CONFIRM_FW_RM_FILTER,
	IDS_BTN_LABEL_ADD,
	IDS_BTN_LABEL_DEL,
	IDS_BTN_LABEL_ALLBLOCK_ENABLE,
	IDS_BTN_LABEL_ALLBLOCK_DISABLE,
	IDS_STATIC_TEXT_IPADDR,
	IDS_STATIC_TEXT_PORT,
	IDS_STATIC_TEXT_FQDN,
	IDS_STATIC_TEXT_PROTOCOL,
	IDS_STATIC_TEXT_URL,
	IDS_STATIC_TEXT_PROCESS,
	IDS_STATIC_TEXT_ACTION,
	IDS_STATIC_TEXT_ALLBLOCK_ENABLE,
	IDS_COMBO_SEL_PERMIT,
	IDS_COMBO_SEL_BLOCK,
	IDS_ERROR_FW_EXIT,
	IDS_STATIC_TEXT_SERV,
};

const std::array<std::pair<UINT, UINT>, 3> ipAddrCheckIDAndEditID =
{
	std::pair<UINT,UINT>(IDC_CHECK_ADDR,IDC_IPADDRESS),
	std::pair<UINT,UINT>(IDC_CHECK_FQDN,IDC_EDIT_FQDN),
	std::pair<UINT,UINT>(IDC_CHECK_URL,IDC_EDIT_URL),
};

const std::array<std::pair<UINT, UINT>, 3> portCheckIDAndEditID =
{
	std::pair<UINT,UINT>(IDC_CHECK_PORT,IDC_EDIT_PORT),
	std::pair<UINT,UINT>(IDC_CHECK_PROTOCOL,IDC_EDIT_PROTOCOL),
	std::pair<UINT,UINT>(IDC_CHECK_URL,IDC_EDIT_URL),
};

tstring StrResourceFromStringTable(UINT dwResourceID)
{
	constexpr auto size = 256;
	std::vector<TCHAR> szResource(size);
	LoadString(GetModuleHandle(nullptr), dwResourceID, szResource.data(), szResource.size());
	return tstring(szResource.data());
}

void BuildStringMap()
{
	for (const auto& elem : stringTableIDs)
	{
		tstring sLabel = StrResourceFromStringTable(elem);
		stringMap[elem] = sLabel;
	}
}