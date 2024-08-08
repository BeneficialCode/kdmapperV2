#pragma once
#include <Windows.h>
#include <Psapi.h>

struct KernelHelper final {
	KernelHelper();

	static bool GetKernelBaseAddr();
	static ULONG_PTR GetSymbolOffset(PCSTR name);

private:
	static inline HMODULE _hNtos = NULL;

public:
	static inline ULONG_PTR _kernelBase = 0;
};