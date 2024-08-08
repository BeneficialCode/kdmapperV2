#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif
  int AllocNonpagedPool(std::size_t size, std::uintptr_t* kernel_addr);

  int FreeNonpagedPool(std::uintptr_t kernel_addr);

  int WriteTo(std::uintptr_t kernel_addr, std::uint8_t* src, std::size_t size);

  int ReadFrom(std::uintptr_t kernel_addr, std::uint8_t* dst, std::size_t size);

  int JumpTo(std::uintptr_t kernel_addr, void* arg1, void* arg2, std::uintptr_t* status);

#ifdef __cplusplus
}
#endif
