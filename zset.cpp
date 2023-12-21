#include "zset.h"
#include "avl.h"
#include "common.h"
#include "hashtable.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static ZNode *znode_new(const char *name, size_t len, double score) {
    ZNode *node = (ZNode *)malloc(sizeof(ZNode) + len);
    assert(node);
    avl_init(&node->tree);
    node->hmap.next = nullptr;
    node->hmap.hcode = str_hash((uint8_t *)name, len);
    node->score = score;
    node->len = len;
    memcpy(&node->name[0], name, len);
    return node;
}

static uint32_t min(size_t lhs, size_t rhs) { return lhs < rhs ? lhs : rhs; }

// compare by the (score, name) tuple
static bool zless(AVLNode *lhs, double score, const char *name, size_t len) {
    ZNode *zl = getStructPtr(lhs, &ZNode::tree);
    if (zl->score != score) {
        return zl->score < score;
    }
    int rv = memcmp(zl->name, name, min(zl->len, len));
    if (rv != 0) {
        return rv < 0;
    }
    return zl->len < len;
}

static bool zless(AVLNode *lhs, AVLNode *rhs) {
    ZNode *zr = getStructPtr(rhs, &ZNode::tree);
    return zless(lhs, zr->score, zr->name, zr->len);
}

// insert into the AVLtree
static void tree_add(ZSet *zset, ZNode *node) {
    if (!zset->tree) {
        zset->tree = &node->tree;
        return;
    }

    AVLNode *cur = zset->tree;
    while (true) {
        AVLNode **from = zless(&node->tree, cur) ? &cur->left : &cur->right;
        if (!*from) {
            *from = &node->tree;
            node->tree.parent = cur;
            zset->tree = avl_fix(&node->tree);
            break;
        }
        cur = *from;
    }
}

// update the score of an existing node (AVL tree reinsertion)
// if score changes, the postion of avlnode maybe changed
// so we need to update score and reinsert this node
static void zset_update(ZSet *zset, ZNode *node, double score) {
    if (node->score == score) {
        return;
    }
    zset->tree = avl_del(&node->tree);
    node->score = score;
    avl_init(&node->tree);
    tree_add(zset, node);
}

// add a new (soce, name) tuple, or update the score of the existing tuple
bool zset_add(ZSet *zset, const char *name, size_t len, double score) {
    ZNode *node = zset_lookup(zset, name, len);
    if (node) {
        zset_update(zset, node, score);
        return false;
    } else {
        node = znode_new(name, len, score);
        hm_insert(&zset->hmap, &node->hmap);
        tree_add(zset, node);
        return true;
    }
}

// a helper structure for the hashtable lookup
struct Hkey {
    HNode node;
    const char *name = nullptr;
    size_t len = 0;
};

static bool hcmp(HNode *node, HNode *key) {
    if (node->hcode != key->hcode) {
        return false;
    }
    ZNode *znode = getStructPtr(node, &ZNode::hmap);
    Hkey *hkey = getStructPtr(key, &Hkey::node);

    if (znode->len != hkey->len) {
        return false;
    }
    return 0 == memcpy(znode->name, hkey->name, znode->len);
}

// lookup by name
ZNode *zset_lookup(ZSet *zset, const char *name, size_t len) {
    if (!zset->tree) {
        return nullptr;
    }

    Hkey key;
    key.node.hcode = str_hash((uint8_t *)name, len);
    key.name = name;
    key.len = len;
    HNode *found = hm_lookup(&zset->hmap, &key.node, &hcmp);
    if (!found) {
        return nullptr;
    }
    return getStructPtr(found, &ZNode::hmap);
}

// deletion by name
ZNode *zset_pop(ZSet *zset, const char *name, size_t len) {
    if (!zset->tree) {
        return nullptr;
    }

    Hkey key;
    key.node.hcode = str_hash((uint8_t *)name, len);
    key.name = name;
    key.len = len;
    HNode *found = hm_lookup(&zset->hmap, &key.node, &hcmp);
    if (!found) {
        return nullptr;
    }

    ZNode *node = getStructPtr(found, &ZNode::hmap);
    zset->tree = avl_del(&node->tree);
    return node;
}

// find the (score, name) tuple that is greater or equal to the argument
// then offset relative to it
ZNode *zset_query(ZSet *zset, double score, const char *name, size_t len,
                  int64_t offset) {
    AVLNode *found = nullptr;
    AVLNode *cur = zset->tree;
    while (cur) {
        if (zless(cur, score, name, len)) {
            cur = cur->right;
        } else {
            found = cur;
            cur = cur->left;
        }
    }
    if (found) {
        found = avl_offset(found, offset);
    }

    return found ? getStructPtr(found, &ZNode::tree) : nullptr;
}

void znode_del(ZNode *node) { free(node); }

static void tree_dispose(AVLNode *node) {
    if (!node) {
        return;
    }
    tree_dispose(node->left);
    tree_dispose(node->right);
    znode_del(getStructPtr(node, &ZNode::tree));
}
void zset_dispose(ZSet *zset) {
    tree_dispose(zset->tree);
    hm_destroy(&zset->hmap);
}
