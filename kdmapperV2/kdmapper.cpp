#include "kdmapper.hpp"
#include "exp.h"
#include "kernel_helper.hpp"

#pragma comment(lib,"runshellcode_lib.lib")

uint64_t kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, bool mdlMode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	uint64_t kernel_image_base = 0;
	uint64_t mdlptr = 0;
	// TODO: get the kernel_image_base
	AllocNonpagedPool(image_size, &kernel_image_base);

	do {
		if (!kernel_image_base) {
			Log(L"[-] Failed to allocate remote image in kernel" << std::endl);
			break;
		}

		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		uint64_t realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(portable_executable::GetImports(local_image_base))) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// TODO: Write fixed image to kernel
		WriteTo(realBase, (uint8_t*)((uintptr_t)local_image_base + (destroyHeader ? 
			TotalVirtualHeaderSize : 0)),
			image_size);

		// Call driver entry point

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size, mdlptr)) {
				Log(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		uintptr_t status = 0;
		JumpTo(address_of_entry_point, nullptr, nullptr, (uintptr_t*)&status);
		if (exitCode)
			*exitCode = status;

		Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		if (free) {
			FreeNonpagedPool(realBase);
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	return 0;
}

void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(portable_executable::vec_imports imports) {
	KernelHelper helper;
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = helper.GetSymbolOffset(
				current_function_data.name.c_str()) + KernelHelper::_kernelBase;
			*current_function_data.address = function_address;
		}
	}

	return true;
}
