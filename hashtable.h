// hashtable node, should be embedded int to the payload
#include <cstddef>
#include <cstdint>

struct HNode {
    HNode *next = nullptr;
    uint64_t hcode = 0;
};

// a simple fix-sized hashtable
struct HTab {
    HNode **tab = nullptr;
    size_t mask = 0;
    size_t size = 0;
};

// the real hashtable interface
// it uses 2 hashtables to progressive resizing
struct HMap {
    HTab ht1;
    HTab ht2;
    size_t resizing_pos = 0;
};

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *));

void hm_insert(HMap *hmap, HNode *node);

HNode *hm_pop(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *));

void hm_destroy(HMap *hmap);
