#include "common.h"
#include "hashtable.h"
#include "zset.h"
#include <arpa/inet.h>
#include <assert.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/_types/_fd_def.h>
#include <sys/_types/_socklen_t.h>
#include <sys/_types/_ssize_t.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

const unsigned MAX_MSG_SIZE = 4096;

const unsigned MAX_MSG_NUM = 1024;

const unsigned MAX_EVENTS = 1024;

static void msg(const char *msg) { std::cerr << msg << std::endl; }

static void die(const char *msg) {
    int err = errno;
    std::cerr << "[" << err << "] " << msg << std::endl;
    exit(EXIT_FAILURE);
}

static void fd_set_nb(int fd) {
    errno = 0;
    int flag = fcntl(fd, F_GETFL);
    if (errno) {
        die("get file state error");
    }
    errno = 0;
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
    if (errno) {
        die("set file nb error");
    }
}

enum class STATE { REQ, RES, END };

struct Conn {
    int fd = -1;
    STATE state;
    // buffer for reading
    size_t rbuf_size = 0;
    uint8_t rbuf[4 + MAX_MSG_SIZE]{};
    // buffer for writing
    size_t wbuf_size = 0;
    size_t wbuf_sent = 0;
    uint8_t wbuf[4 + MAX_MSG_SIZE]{};
};

static int accept_new_conn(std::map<int, Conn *> &fd2conn, int fd) {
    // accept
    struct sockaddr_in clnt_addr {};
    socklen_t clnt_addr_len = sizeof(clnt_addr);
    int connfd = accept(fd, (sockaddr *)&clnt_addr, &clnt_addr_len);
    if (connfd < 0) {
        msg("accept error");
        return -1;
    }

    // set connfd nb
    fd_set_nb(connfd);

    // create Conn struct
    struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));
    if (!conn) {
        msg("malloc error");
        close(connfd);
        return -1;
    }

    conn->fd = connfd;
    conn->state = STATE::REQ;
    conn->rbuf_size = 0;
    conn->wbuf_sent = 0;
    conn->wbuf_size = 0;

    // put conn in map
    fd2conn[connfd] = conn;
    return connfd;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

static uint32_t parse_req(const uint8_t *data, size_t len,
                          std::vector<std::string> &out) {
    if (len < 4) {
        return -1;
    }

    uint32_t n = 0;
    memcpy(&n, &data[0], 4);
    if (n > MAX_MSG_NUM) {
        return -1;
    }

    size_t pos = 4;
    while (n--) {
        if (pos + 4 > len) {
            return -1;
        }

        uint32_t sz = 0;
        memcpy(&sz, &data[pos], 4);
        if (pos + 4 + sz > len) {
            return -1;
        }
        out.push_back(std::string((char *)&data[pos + 4], sz));
        pos += 4 + sz;
    }

    if (pos != len) {
        return -1;
    }
    return 0;
}

// the data structure for the key space
static struct {
    HMap db;
} g_data;

enum class T { STR, ZSET };

/* // the structure for the key */
/* struct Entry { */
/*     struct HNode node; */
/*     std::string key; */
/*     std::string val; */
/* }; */
/* Instead of making our data structure contain data, the hashtable node
 * structure is embedded into the payload data. This is the standard way of
 * creating generic data structures in C. */
/**/
/* Besides making the data structure fully generic, this technique also has the
 * advantage of reducing unnecessary memory management. The structure node is
 * not separately allocated but is part of the payload data, and the data
 * structure code does not own the payload but merely organizes the data. This
 * may be quite a new idea to you if you learned data structures from textbooks,
 * which is probably using void * or C++ templates or even macros. */
struct Entry {
    struct HNode node;
    std::string key;
    std::string val;
    T type = T::STR;
    ZSet *zset = nullptr;
};

// @brief: equal means keys equal
static bool entry_eq(HNode *lhs, HNode *rhs) {
    struct Entry *le = container_of(lhs, struct Entry, node);
    struct Entry *re = container_of(rhs, struct Entry, node);
    return lhs->hcode == rhs->hcode and le->key == re->key;
}

enum class ERR { UNKNOWN = 1, TOOBIG, TYPE, ARG };

// @brief: put SER::NIL into out
static void out_nil(std::string &out) {
    out.push_back(static_cast<char>(SER::NIL));
}

// @brief: out = STR + strlen + str
static void out_str(std::string &out, const std::string &val) {
    out.push_back(static_cast<char>(SER::STR));
    uint32_t len = (uint32_t)val.size();
    out.append((char *)&len, 4);
    out.append(val);
}

// @brief: out = STR + strlen + str
static void out_str(std::string &out, const char *s, size_t size) {
    out.push_back(static_cast<char>(SER::STR));
    uint32_t len = (uint32_t)size;
    out.append((char *)&len, 4);
    out.append(s, len);
}

// @brief: out = INT + int64_t
static void out_int(std::string &out, int64_t val) {
    out.push_back(static_cast<char>(SER::INT));
    out.append((char *)&val, 8);
}

// @brief: out = DBL + double
static void out_dbl(std::string &out, double val) {
    out.push_back(static_cast<char>(SER::DBL));
    out.append((char *)&val, 8);
}

// @brief: out = ERR + ERR::code + msglen + msg
static void out_err(std::string &out, ERR code, const std::string &msg) {
    out.push_back(static_cast<char>(SER::ERR));
    out.append((char *)&code, 4);
    uint32_t len = (uint32_t)msg.size();
    out.append((char *)&len, 4);
    out.append(msg);
}

// @brief: out = ARR + uint32_t n
static void out_arr(std::string &out, uint32_t n) {
    out.push_back(static_cast<char>(SER::ARR));
    out.append((char *)&n, 4);
}

// @brief: check if out[0]==ARR, let out[1] = uint32_t n
static void out_update_arr(std::string &out, uint32_t n) {
    assert(out[0] == static_cast<char>(SER::ARR));
    memcpy(&out[1], &n, 4);
}

// @brief: generate out by cmd, type is STR is good
static void do_get(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup((HMap *)&g_data.db, &key.node, &entry_eq);
    if (!node) {
        return out_nil(out);
    }

    Entry *ent = container_of(node, struct Entry, node);
    if (ent->type != T::STR) {
        return out_err(out, ERR::TYPE, "expect string type");
    }

    return out_str(out, ent->val);
}

// @brief: generate out by cmd, set this key value in hashtable not the AVLtree
static void do_set(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node) {
        Entry *ent = container_of(node, struct Entry, node);
        if (ent->type != T::STR) {
            return out_err(out, ERR::TYPE, "expect string type");
        }
        ent->val.swap(cmd[2]);
    } else {
        Entry *ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->val.swap(cmd[2]);
        hm_insert(&g_data.db, &ent->node);
    }
    return out_nil(out);
}

// @brief: if type is ZSET, call zset_dispose, delete the AVLtree & hashtable
static void entry_del(Entry *ent) {
    switch (static_cast<T>(ent->type)) {
    case T::ZSET:
        zset_dispose(ent->zset);
        delete ent->zset;
        break;
    case T::STR:
        break;
    }
    delete ent;
}

// @brief:
static void do_del(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_pop(&g_data.db, &key.node, &entry_eq);
    if (node) {
        entry_del(container_of(node, struct Entry, node));
    }
    return out_int(out, node ? 1 : 0);
}

// Travel the HTab
static void h_scan(HTab *tab, void (*f)(HNode *, void *), void *arg) {
    if (tab->size == 0) {
        return;
    }
    for (int i = 0; i < tab->mask + 1; ++i) {
        HNode *node = tab->tab[i];
        while (node) {
            f(node, arg);
            node = node->next;
        }
    }
}

// find key by the node pointer
static void cb_scan(HNode *node, void *arg) {
    std::string &out = *(std::string *)arg;
    out_str(out, container_of(node, struct Entry, node)->key);
}

static void do_keys(std::vector<std::string> &cmd, std::string &out) {
    (void)cmd;
    out_arr(out, (uint32_t)hm_size(&g_data.db));
    h_scan(&g_data.db.ht1, &cb_scan, &out);
    h_scan(&g_data.db.ht2, &cb_scan, &out);
}

static bool str2dbl(const std::string &s, double &out) {
    char *endp = nullptr;
    out = strtod(s.c_str(), &endp);
    return endp == s.c_str() + s.size() && !isnan(out);
}

static bool str2int(const std::string &s, int64_t &out) {
    char *endp = nullptr;
    out = strtoll(s.c_str(), &endp, 10);
    return endp == s.c_str() + s.size();
}

// zadd zset score name
static void do_zadd(std::vector<std::string> &cmd, std::string &out) {
    double score = 0;
    if (!str2dbl(cmd[2], score)) {
        return out_err(out, ERR::ARG, "expect fd number");
    }

    // lookup or create the zset, a database name
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);

    Entry *ent = nullptr;
    if (!hnode) { // database does not exist
        ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->type = T::ZSET;
        ent->zset = new ZSet;
        hm_insert(&g_data.db, &ent->node);
    } else { // database exists
        ent = container_of(hnode, struct Entry, node);
        if (ent->type != T::ZSET) {
            return out_err(out, ERR::TYPE, "expect zset");
        }
    }

    // add or update the tuple
    const std::string &name = cmd[3];
    bool added = zset_add(ent->zset, name.data(), name.size(), score);
    return out_int(out, (int64_t)added);
}

static bool expect_zset(std::string &out, std::string &s, Entry **ent) {
    Entry key;
    key.key.swap(s);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!hnode) {
        out_nil(out);
        return false;
    }

    *ent = container_of(hnode, struct Entry, node);
    if ((*ent)->type != T::ZSET) {
        out_err(out, ERR::TYPE, "expect zset");
        return false;
    }
    return true;
}

// zrem zset name
static void do_zrem(std::vector<std::string> &cmd, std::string &out) {
    Entry *ent = nullptr;
    if (!expect_zset(out, cmd[1], &ent)) {
        return;
    }

    const std::string &name = cmd[2];
    ZNode *znode = zset_pop(ent->zset, name.data(), name.size());
    if (znode) {
        znode_del(znode);
    }
    return out_int(out, znode ? 1 : 0);
}

// zscore zset name
static void do_zscore(std::vector<std::string> &cmd, std::string &out) {
    Entry *ent = nullptr;
    if (!expect_zset(out, cmd[1], &ent)) {
        return;
    }

    const std::string &name = cmd[2];
    ZNode *znode = zset_lookup(ent->zset, name.data(), name.size());
    return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// zquery zset scorename offset limit
static void do_zquery(std::vector<std::string> &cmd, std::string &out) {
    // parse args
    double score = 0;
    if (!str2dbl(cmd[2], score)) {
        return out_err(out, ERR::ARG, "expect fp number");
    }
    const std::string &name = cmd[3];
    int64_t limit = 0;
    int64_t offset = 0;
    if (!str2int(cmd[4], offset)) {
        return out_err(out, ERR::ARG, "expect int");
    }
    if (!str2int(cmd[5], limit)) {
        return out_err(out, ERR::ARG, "expect int");
    }

    // get the zset
    Entry *ent = nullptr;
    if (!expect_zset(out, cmd[1], &ent)) {
        if (static_cast<SER>(out[0]) == SER::NIL) {
            out.clear();
            out_arr(out, 0);
        }
        return;
    }

    // look up the tuple
    if (limit <= 0) {
        return out_arr(out, 0);
    }

    ZNode *znode =
        zset_query(ent->zset, score, name.data(), name.size(), offset);

    // output
    out_arr(out, 0);
    uint32_t n = 0;
    while (znode && (int64_t)n < limit) {
        out_str(out, znode->name, znode->len);
        out_dbl(out, znode->score);
        znode = container_of(avl_offset(&znode->tree, +1), struct ZNode, tree);
        n += 2;
    }
    return out_update_arr(out, n);
}

static bool cmd_is(const std::string &word, const char *cmd) {
    return 0 == strcasecmp(word.c_str(), cmd);
}

static void do_request(std::vector<std::string> &cmd, std::string &out) {
    if (cmd.size() == 1 and cmd_is(cmd[0], "keys")) {
        do_keys(cmd, out);
    } else if (cmd.size() == 2 and cmd_is(cmd[0], "get")) {
        do_get(cmd, out);
    } else if (cmd.size() == 3 and cmd_is(cmd[0], "set")) {
        do_set(cmd, out);
    } else if (cmd.size() == 2 and cmd_is(cmd[0], "del")) {
        do_del(cmd, out);
    } else if (cmd.size() == 4 and cmd_is(cmd[0], "zadd")) {
        do_zadd(cmd, out);
    } else if (cmd.size() == 3 and cmd_is(cmd[0], "zrem")) {
        do_zrem(cmd, out);
    } else if (cmd.size() == 3 and cmd_is(cmd[0], "zscore")) {
        do_zscore(cmd, out);
    } else if (cmd.size() == 6 and cmd_is(cmd[0], "zquery")) {
        do_zquery(cmd, out);
    } else {
        // cmd is not recognized
        out_err(out, ERR::UNKNOWN, "Unknown cmd");
    }
}

static bool try_one_request(Conn *conn) {
    // try to parse a request from the buffer
    if (conn->rbuf_size < 4) {
        // not enough data in the buffer
        return false;
    }

    uint32_t len = 0;
    memcpy(&len, &conn->rbuf[0], 4);
    if (len > MAX_MSG_SIZE) {
        msg("too long");
        conn->state = STATE::END;
        return false;
    }
    if (4 + len > conn->rbuf_size) {
        // not enough data inthe buffer, try next iteration
        return false;
    }

    // parse the request
    std::vector<std::string> cmd;
    if (parse_req(&conn->rbuf[4], len, cmd) != 0) {
        msg("bad req");
        conn->state = STATE::END;
        return false;
    }

    // got one request, generate the response
    std::string out;
    do_request(cmd, out);

    // pack the response into the buffer
    if (4 + out.size() > MAX_MSG_SIZE) {
        out.clear();
        out_err(out, ERR::TOOBIG, "response is too big");
    }
    uint32_t wlen = (uint32_t)out.size();
    memcpy(&conn->wbuf[0], &wlen, 4);
    memcpy(&conn->wbuf[4], out.data(), out.size());
    conn->wbuf_size = 4 + wlen;

    // remove the resonse from the buffer
    // note: frequent memmove is inefficient
    // note: need better handling for production code
    size_t remain = conn->rbuf_size - 4 - len;
    if (remain) {
        memmove(conn->rbuf, &conn->rbuf[4 + len], remain);
    }
    conn->rbuf_size = remain;

    // change state
    conn->state = STATE::RES;
    state_res(conn);

    // continue the outer loop if the request was fully processed
    return (conn->state == STATE::REQ);
}

static bool try_fill_buffer(Conn *conn) {
    // try to fill the buffer
    assert(conn->rbuf_size < sizeof(conn->rbuf));
    ssize_t rv = 0;

    do {
        size_t cap = sizeof(conn->rbuf) - conn->rbuf_size;
        rv = read(conn->fd, &conn->rbuf[conn->rbuf_size], cap);
    } while (rv < 0 and errno == EINTR);

    if (rv < 0 and ((errno == EAGAIN) and (errno == EWOULDBLOCK))) {
        // gotEAGAIN, stop
        return false;
    }
    if (rv < 0) {
        msg("read error");
        conn->state = STATE::END;
        return false;
    }

    if (rv == 0) {
        if (conn->rbuf_size > 0) {
            msg("unexpexted EOF");
        } else {
            msg("EOF");
        }
        conn->state = STATE::END;
        return false;
    }

    conn->rbuf_size += (size_t)rv;
    assert(conn->rbuf_size <= sizeof(conn->rbuf));

    // try to process requests one by one
    // why is there a loop?
    while (try_one_request(conn)) {
    }
    return (conn->state == STATE::REQ);
}

static void state_req(Conn *conn) {
    while (try_fill_buffer(conn)) {
    }
}

static bool try_flush_buffer(Conn *conn) {
    ssize_t rv = 0;
    do {
        size_t remain = conn->wbuf_size - conn->wbuf_sent;
        rv = write(conn->fd, &conn->wbuf[conn->wbuf_sent], remain);
    } while (rv < 0 and errno == EINTR);

    if (rv < 0 && ((errno == EAGAIN) or (errno == EWOULDBLOCK))) {
        return false;
    }

    if (rv < 0) {
        msg("write error");
        conn->state = STATE::END;
        return false;
    }

    conn->wbuf_sent += (size_t)rv;
    assert(conn->wbuf_sent <= conn->wbuf_size);
    if (conn->wbuf_sent == conn->wbuf_size) {
        // response was fully sent, change state abck
        conn->state = STATE::REQ;
        conn->wbuf_size = 0;
        conn->wbuf_sent = 0;
        return false;
    }
    // still got some data in wbuf, could try to write again
    return true;
}

static void state_res(Conn *conn) {
    while (try_flush_buffer(conn)) {
    }
}

static void connection_io(Conn *conn) {
    if (conn->state == STATE::REQ) {
        state_req(conn);
    } else if (conn->state == STATE::RES) {
        state_res(conn);
    } else {
        assert(0);
    }
}

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        die("socket create error");
    }

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    // bind
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr.s_addr);

    int rv = bind(fd, (sockaddr *)&addr, (socklen_t)sizeof(addr));
    if (rv == -1) {
        die("bind error");
    }

    // listen
    rv = listen(fd, SOMAXCONN);
    if (rv == -1) {
        die("bind error");
    }

    // a map of all client connections, keyed by fd
    std::map<int, Conn *> fd2conn;

    // set fd to be nonblocking
    fd_set_nb(fd);

    // event loop
    struct kevent ev[MAX_EVENTS]{};
    EV_SET(&ev[0], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)&fd);

    int kfd = kqueue();
    if (kfd == -1) {
        die("kqueue create error");
    }

    while (true) {

        // put all conn in kevent
        int index = 1;
        for (auto &pair : fd2conn) {
            Conn *temp_conn = pair.second;
            if (temp_conn) {
                short flag = (temp_conn->state == STATE::REQ) ? EVFILT_READ
                                                              : EVFILT_WRITE;
                EV_SET(&ev[index++], pair.first, flag,
                       EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
                       (void *)&pair.first);
            }
        }

        struct kevent active_event[MAX_EVENTS]{};

        // poll for active fds
        rv = kevent(kfd, ev, index, active_event, MAX_EVENTS, nullptr);
        if (rv < 0) {
            die("kevent error");
        }

        // process active connections
        for (int i = 0; i < rv; ++i) {
            if (*(int *)active_event[i].udata == fd) {
                // listen fd
                accept_new_conn(fd2conn, fd);
            } else {
                // connections
                int temp = *(int *)active_event[i].udata;
                Conn *conn = fd2conn[temp];
                connection_io(conn);
                if (conn->state == STATE::END) {
                    close(temp);
                    fd2conn.erase(temp);
                    free(conn);
                }
            }
        }
    }

    return 0;
}
