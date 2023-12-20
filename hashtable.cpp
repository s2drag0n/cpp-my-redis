#include "hashtable.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdlib>

// n must be a power of 2
static void h_init(HTab *htab, size_t n) {
    assert(n > 0 and ((n - 1) & n) == 0);
    htab->tab = (HNode **)calloc(n, sizeof(HNode *));
    htab->mask = n - 1;
    htab->size = 0;
}

// hashtable insertion
static void h_insert(HTab *htab, HNode *node) {
    size_t pos = htab->mask & node->hcode;
    HNode *next = htab->tab[pos];
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

// hashtable look up subroutine
// return value is the address of a parent pointer
// that owns the target node
// which can be used to delete the node
static HNode **h_lookup(HTab *htab, HNode *key, bool (*cmp)(HNode *, HNode *)) {
    if (!htab->tab) {
        return nullptr;
    }

    size_t pos = htab->mask & key->hcode;
    HNode **from = &htab->tab[pos];

    while (*from) {
        if (cmp(*from, key)) {
            return from;
        }
        from = &(*from)->next;
    }
    return nullptr;
}

// remove a node from the chain
static HNode *h_detach(HTab *htab, HNode **from) {
    HNode *node = *from;
    (*from) = (*from)->next;
    htab->size--;
    return node;
}

const size_t k_resizing_work = 128;

static void hm_help_resizing(HMap *hmap) {
    if (hmap->ht2.tab == nullptr) {
        return;
    }

    int n = 0;
    while (n < k_resizing_work and hmap->ht2.size > 0) {
        HNode **from = &hmap->ht2.tab[hmap->resizing_pos];
        if (!*from) {
            hmap->resizing_pos++;
            continue;
        }
        h_insert(&hmap->ht1, h_detach(&hmap->ht2, from));
        n++;
    }

    if (hmap->ht2.size == 0) {
        free(hmap->ht2.tab);
        hmap->ht2 = HTab{};
    }
}

static void hm_start_resizing(HMap *hmap, bool flag) {
    assert(hmap->ht2.tab == nullptr);
    hmap->ht2 = hmap->ht1;
    if (flag) {
        h_init(&hmap->ht1, (hmap->ht2.mask + 1) * 2);
    } else {
        h_init(&hmap->ht1, std::max<int>((hmap->ht2.mask + 1) / 2, 2));
    }
    hmap->resizing_pos = 0;
}

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *)) {
    hm_help_resizing(hmap);
    HNode **from = h_lookup(&hmap->ht1, key, cmp);
    if (!from) {
        from = h_lookup(&hmap->ht2, key, cmp);
    }
    return from ? *from : nullptr;
}

const size_t k_max_load_factor = 8;
const size_t k_min_load_factor = 1;

void hm_insert(HMap *hmap, HNode *node) {
    if (!hmap->ht1.tab) {
        h_init(&hmap->ht1, 4);
    }
    h_insert(&hmap->ht1, node);

    if (!hmap->ht2.tab) {
        // check whether we need to resize
        size_t load_fator = hmap->ht1.size / (hmap->ht1.mask + 1);
        if (load_fator >= k_max_load_factor) {
            hm_start_resizing(hmap, true);
        }
    }
    hm_help_resizing(hmap);
}

HNode *hm_pop(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *)) {
    hm_help_resizing(hmap);
    HNode **from = h_lookup(&hmap->ht1, key, cmp);
    if (from) {
        return h_detach(&hmap->ht1, from);
    }
    from = h_lookup(&hmap->ht2, key, cmp);
    if (from) {
        return h_detach(&hmap->ht2, from);
    }
    if (!hmap->ht2.tab) {
        // check whether we need to resize
        size_t load_fator = hmap->ht1.size / (hmap->ht1.mask + 1);
        if (load_fator <= k_min_load_factor) {
            hm_start_resizing(hmap, false);
        }
    }

    return nullptr;
}

size_t hm_size(HMap *hmap) { return hmap->ht1.size + hmap->ht2.size; }

void hm_destroy(HMap *hmap) {
    assert(hmap->ht1.size + hmap->ht2.size == 0);
    free(hmap->ht1.tab);
    free(hmap->ht2.tab);
    *hmap = HMap{};
}
