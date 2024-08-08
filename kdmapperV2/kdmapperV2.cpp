// kdmapperV2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "kdmapper.hpp"



LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: kdmapperV2.exe driver" << std::endl);
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	UNREFERENCED_PARAMETER(mdlptr);
	Log("[+] Callback example called" << std::endl);

	/*
	This callback occurs before call driver entry and
	can be usefull to pass more customized params in
	the last step of the mapping procedure since you
	know now the mapping address and other things
	*/
	return true;
}

int wmain(const int argc, wchar_t** argv)
{
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		return -1;
	}

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, true, false, false, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		return -1;
	}

	Log(L"[+] success" << std::endl);
}

