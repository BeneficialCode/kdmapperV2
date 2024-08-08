#include "kernel_helper.hpp"

KernelHelper::KernelHelper() {
	GetKernelBaseAddr();
	_hNtos = LoadLibraryEx(L"ntoskrnl.exe",nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

bool KernelHelper::GetKernelBaseAddr() {
	DWORD size;

	if (EnumDeviceDrivers(nullptr, 0, &size)) {
		LPVOID* drivers = (LPVOID*)malloc(size);
		if (drivers) {
			if (EnumDeviceDrivers(drivers, size, &size)) {
				_kernelBase = reinterpret_cast<ULONG_PTR>(drivers[0]);
			}
		}
		if (drivers != nullptr) {
			free(drivers);
		}
	}
	return _kernelBase ? true : false;
}

ULONG_PTR KernelHelper::GetSymbolOffset(PCSTR name) {
	return reinterpret_cast<ULONG_PTR>(GetProcAddress(_hNtos, name)) - (ULONG_PTR)_hNtos;
}