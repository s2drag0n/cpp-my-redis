#include "avl.h"
#include <cstdint>
#include <unistd.h>

static uint32_t avl_depth(AVLNode *node) { return node ? node->depth : 0; }

static uint32_t avl_cnt(AVLNode *node) { return node ? node->cnt : 0; }

static uint32_t max(uint32_t lhs, uint32_t rhs) {
    return lhs < rhs ? rhs : lhs;
}

// @brief: maintaining the depth and cnt field
static void avl_update(AVLNode *node) {
    node->depth = 1 + max(avl_depth(node->left), avl_depth(node->right));
    node->cnt = 1 + avl_cnt(node->left) + avl_cnt(node->right);
}

// @brief: left rotation a tree
// @reurn: the new root of the tree
static AVLNode *rot_left(AVLNode *node) {
    /*
     *     b           d
     *    / \         /
     *   a   d  ==>  b
     *      /       / \
     *     c       a   c
     */
    AVLNode *new_node = node->right;
    if (new_node->left) {
        new_node->left->parent = node;
    }
    node->right = new_node->left;
    new_node->left = node;
    new_node->parent = node->parent;
    node->parent = new_node;
    avl_update(node);
    avl_update(new_node);
    return new_node;
}

// @brief: right rotation a tree
// @reurn: the new root of the tree
static AVLNode *rot_right(AVLNode *node) {
    /*
     *     b           d
     *    / \           \
     *   d   a  ==>     b
     *   \             / \
     *   c            c   a
     */
    AVLNode *new_node = node->left;
    if (new_node->right) {
        new_node->right->parent = node;
    }
    node->left = new_node->right;
    new_node->parent = node->parent;
    new_node->right = node;
    node->parent = new_node;
    avl_update(node);
    avl_update(new_node);
    return new_node;
}

// @brief: when the left subtree is too deep, fix it
// @return: return new left subtree
static AVLNode *avl_fix_left(AVLNode *root) {
    if (avl_depth(root->left->left) < avl_depth(root->left->right)) {
        root->left = rot_left(root->left);
    }
    return rot_right(root);
}

// @brief: when the right subtree is too deep, fix it
// @return: return new left subtree
static AVLNode *avl_fix_right(AVLNode *root) {
    /*   b           b           d
     *  / \         / \         / \
     * a   c  ==>  a   d  ==>  b   c
     *    /             \     /
     *   d               c   a
     */
    if (avl_depth(root->right->right) < avl_depth(root->right->left)) {
        root->right = rot_right(root->right);
    }
    return rot_left(root);
}

// @brief: fix imbalanced nodes and maintian invariants until the root is
// reached
// @return: new whole tree root
AVLNode *avl_fix(AVLNode *node) {
    while (true) {
        avl_update(node);
        uint32_t l = avl_depth(node->left);
        uint32_t r = avl_depth(node->right);
        // pointer from not only has the parent info and also point out node is
        // a left or right subtree
        AVLNode **from = nullptr;
        if (node->parent) {
            from = (node->parent->left == node) ? &node->parent->left
                                                : &node->parent->right;
        }
        if (l == r + 2) {
            node = avl_fix_left(node);
        } else if (l + 2 == r) {
            node = avl_fix_right(node);
        }

        if (!from) {
            return node;
        }
        *from = node;
        node = node->parent;
    }
}

// @brief: detach a node
// @return: the new root of the tree
AVLNode *avl_del(AVLNode *node) {
    if (node->right == nullptr) {
        // no right subtree, replace the node with the left subtree
        // link the left subtree to the parent
        AVLNode *parent = node->parent;
        if (node->left) {
            node->left->parent = parent;
        }
        if (parent) {
            // attach the left subtree tobe the parent
            (parent->left == node ? parent->left : parent->right) = node->left;
            return avl_fix(parent);
        } else {
            // remove root
            return node->left;
        }
    }
    // swap the node with its next sibing
    AVLNode *victim = node->right;
    while (victim->left) {
        victim = victim->left;
    }
    AVLNode *root = avl_del(victim);

    *victim = *node;
    if (victim->left) {
        victim->left->parent = victim;
    }
    if (victim->right) {
        victim->right->parent = victim;
    }
    AVLNode *parent = node->parent;
    if (parent) {
        (parent->left == node ? parent->left : parent->right) = victim;
        return root;
    } else {
        // remove root?
        return victim;
    }
}

AVLNode *avl_offset(AVLNode *node, int64_t offset) {
    int64_t pos = 0;
    while (offset != pos) {
        if (pos < offset && pos + avl_cnt(node->right) >= offset) {
            node = node->right;
            pos += avl_cnt(node->left) + 1;
        } else if (pos > offset && pos - avl_cnt(node->left) <= offset) {
            node = node->left;
            pos -= avl_cnt(node->right);
        } else {
            // go to the parent
            AVLNode *parent = node->parent;
            if (!parent) {
                return nullptr;
            }
            if (parent->left == node) {
                pos += avl_cnt(node->right) + 1;
            } else {
                pos -= avl_cnt(node->left) + 1;
            }
            node = parent;
        }
    }
    return node;
}
