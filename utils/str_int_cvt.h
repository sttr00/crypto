#ifndef __utils_str_int_cvt_h__
#define __utils_str_int_cvt_h__

#include <string>
#include <stdint.h>

uint32_t str_to_uint32(const std::string &s, int *ppos = nullptr, bool *ok = nullptr);
uint64_t str_to_uint64(const std::string &s, int *ppos = nullptr, bool *ok = nullptr);

int32_t str_to_int32(const std::string &s, int *ppos = nullptr, bool *ok = nullptr);
int64_t str_to_int64(const std::string &s, int *ppos = nullptr, bool *ok = nullptr);

void uint32_to_str(std::string &s, uint32_t val);
void uint64_to_str(std::string &s, uint64_t val);

void int32_to_str(std::string &s, int32_t val);
void int64_to_str(std::string &s, int64_t val);

std::string uint32_to_str(uint32_t val);
std::string uint64_to_str(uint64_t val);

std::string int32_to_str(int32_t val);
std::string int64_to_str(int64_t val);

#endif // __utils_str_int_cvt_h__
