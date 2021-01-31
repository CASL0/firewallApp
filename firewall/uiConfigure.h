#pragma once
#include <Windows.h>
#include <map>
#include <string>

void InitButton(HWND hWndParent, std::map<std::string, HWND>& hWndButton);
void InitEdit(HWND hWndParent, std::map<std::string, HWND>& hWndEdit);
void InitCheckBox(HWND hWndParent, std::map<std::string, HWND>& hWndCheckBox);
void InitComboBox(HWND hWndParent, HWND& hWndCombo);
