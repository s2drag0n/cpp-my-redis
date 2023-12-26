#pragma once
#include <cstddef>
#include <cstdint>
struct HeapItem {
    uint64_t val = 0;
    size_t *ref = nullptr;
};
void heap_update(HeapItem *a, size_t pos, size_t len);
