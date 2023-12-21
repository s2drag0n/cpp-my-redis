#pragma once

#include <cstddef>
#include <cstdint>

template <typename T, typename U, typename V>
T *getStructPtr(U *memberPtr, V T::*member) {
    // 计算结构体中成员的偏移量
    size_t offset = offsetof(T, node);

    // 将成员指针减去偏移量，得到结构体指针
    return reinterpret_cast<T *>(reinterpret_cast<char *>(memberPtr) - offset);
}

inline uint64_t str_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h = (h + data[i]) * 0x01000193;
    }
    return h;
}

enum class SER { NIL, ERR, STR, INT, ARR };
