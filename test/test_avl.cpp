#include "avl.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>

template <typename T, typename U, typename V>
T *getStructPtr(U *memberPtr, V T::*member) {
    // 计算结构体中成员的偏移量
    size_t offset = offsetof(T, node);

    // 将成员指针减去偏移量，得到结构体指针
    return reinterpret_cast<T *>(reinterpret_cast<char *>(memberPtr) - offset);
}

struct Data {
    AVLNode node;
    uint32_t val = 0;
};

struct Container {
    AVLNode *root = NULL;
};

static void add(Container &c, uint32_t val) {
    // build the node to save the val
    Data *data = new Data();
    avl_init(&data->node);
    data->val = val;

    // if Container has no data, let new node to be root
    if (!c.root) {
        c.root = &data->node;
        return;
    }

    AVLNode *cur = c.root;

    while (true) {
        // nb from !!!👍
        AVLNode **from = (val < getStructPtr(cur, &Data::node)->val)
                             ? &cur->left
                             : &cur->right;
        if (!*from) {
            *from = &data->node;
            data->node.parent = cur;
            c.root = avl_fix(&data->node);
            break;
        }
        cur = *from;
    }
}

static bool del(Container &c, uint32_t val) {
    AVLNode *cur = c.root;
    while (cur) {
        uint32_t node_val = getStructPtr(cur, &Data::node)->val;
        if (node_val == val) {
            break;
        }
        cur = (val < node_val) ? cur->left : cur->right;
    }

    if (!cur) {
        return false;
    }

    c.root = avl_del(cur);
    delete getStructPtr(cur, &Data::node);
    return true;
}

static void avl_verify(AVLNode *parent, AVLNode *node) {
    if (!node) {
        return;
    }
    assert(node->parent == parent);
    avl_verify(node, node->left);
    avl_verify(node, node->right);

    assert(node->cnt == 1 + avl_cnt(node->left) + avl_cnt(node->right));

    uint32_t l = avl_depth(node->left);
    uint32_t r = avl_depth(node->right);
    assert(l == r or l + 1 == r or l - 1 == r);
    assert(node->depth == 1 + max(l, r));

    uint32_t val = getStructPtr(node, &Data::node)->val;
    if (node->left) {
        assert(node->left->parent == node);
        assert(getStructPtr(node->left, &Data::node)->val <= val);
    }
    if (node->right) {
        assert(node->right->parent == node);
        assert(getStructPtr(node->right, &Data::node)->val >= val);
    }
}

static void extract(AVLNode *node, std::multiset<uint32_t> &extracted) {
    if (!node) {
        return;
    }
    extract(node->left, extracted);
    extracted.insert(getStructPtr(node, &Data::node)->val);
    extract(node->right, extracted);
}

static void container_verify(Container &c, const std::multiset<uint32_t> &ref) {
    avl_verify(nullptr, c.root);
    assert(avl_cnt(c.root) == ref.size());
    std::multiset<uint32_t> extracted;
    extract(c.root, extracted);
    assert(extracted == ref);
}

static void dispose(Container &c) {
    while (c.root) {
        AVLNode *node = c.root;
        c.root = avl_del(c.root);
        delete getStructPtr(node, &Data::node);
    }
}

static void test_insert(uint32_t sz) {
    for (uint32_t val = 0; val < sz; ++val) {
        Container c;
        std::multiset<uint32_t> ref;
        for (uint32_t i = 0; i < sz; ++i) {
            if (i == val) {
                continue;
            }
            add(c, i);
            ref.insert(i);
        }
        container_verify(c, ref);
        add(c, val);
        ref.insert(val);
        container_verify(c, ref);
        dispose(c);
    }
}

static void test_insert_dup(uint32_t sz) {
    for (uint32_t val = 0; val < sz; val++) {
        Container c;
        std::multiset<uint32_t> ref;
        for (uint32_t i = 0; i < sz; ++i) {
            add(c, i);
            ref.insert(i);
        }
        container_verify(c, ref);

        add(c, val);
        ref.insert(val);
        container_verify(c, ref);
        dispose(c);
    }
}

static void test_remove(uint32_t sz) {
    for (uint32_t val = 0; val < sz; val++) {
        Container c;
        std::multiset<uint32_t> ref;
        for (uint32_t i = 0; i < sz; ++i) {
            add(c, i);
            ref.insert(i);
        }
        container_verify(c, ref);

        assert(del(c, val));
        ref.erase(val);
        container_verify(c, ref);
        dispose(c);
    }
}

int main() {
    Container c;

    // some quick tests
    container_verify(c, {});
    add(c, 123);
    container_verify(c, {123});
    assert(!del(c, 124));
    assert(del(c, 123));
    container_verify(c, {});

    // sequential insertion
    std::multiset<uint32_t> ref;
    for (uint32_t i = 0; i < 1000; i += 3) {
        add(c, i);
        ref.insert(i);
        container_verify(c, ref);
    }

    // random insertion
    for (uint32_t i = 0; i < 100; i++) {
        uint32_t val = (uint32_t)rand() % 1000;
        add(c, val);
        ref.insert(val);
        container_verify(c, ref);
    }

    // random deletion
    for (uint32_t i = 0; i < 100; i++) {
        uint32_t val = (uint32_t)rand() % 1000;
        auto it = ref.find(val);
        if (it == ref.end()) {
            assert(!del(c, val));
        } else {
            assert(del(c, val));
            ref.erase(it);
        }
        container_verify(c, ref);
    }

    // insertion/deletion at various positions
    for (uint32_t i = 0; i < 200; ++i) {
        test_insert(i);
        test_insert_dup(i);
        test_remove(i);
    }

    dispose(c);
    return 0;
}
