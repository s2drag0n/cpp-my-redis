#include "hashtable.h"
#include <arpa/inet.h>
#include <assert.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
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

struct Entry {
    struct HNode node;
    std::string key;
    std::string val;
};

static struct Entry *getStructPtr(HNode *memberPtr) {
    // 计算结构体中成员的偏移量
    size_t offset = offsetof(struct Entry, node);

    // 将成员指针减去偏移量，得到结构体指针
    return (struct Entry *)((char *)memberPtr - offset);
}
static bool entry_eq(HNode *lhs, HNode *rhs) {
    struct Entry *le = getStructPtr(lhs);
    struct Entry *re = getStructPtr(rhs);
    return lhs->hcode == rhs->hcode and le->key == re->key;
}

static uint64_t str_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) {
        h = (h + data[i]) * 0x01000193;
    }
    return h;
}

enum class ERR { UNKNOWN, TOOBIG };

enum class SER { NIL, ERR, STR, INT, ARR };

static void out_nil(std::string &out) {
    out.push_back(static_cast<char>(SER::NIL));
}

static void out_str(std::string &out, const std::string &val) {
    out.push_back(static_cast<char>(SER::STR));
    uint32_t len = (uint32_t)val.size();
    out.append((char *)&len, 4);
    out.append(val);
}

static void out_int(std::string &out, int64_t val) {
    out.push_back(static_cast<char>(SER::INT));
    out.append((char *)&val, 8);
}

static void out_err(std::string &out, int32_t code, const std::string &msg) {
    out.push_back(static_cast<char>(SER::ERR));
    out.append((char *)&code, 4);
    uint32_t len = (uint32_t)msg.size();
    out.append((char *)&len, 4);
    out.append(msg);
}

static void out_arr(std::string &out, uint32_t n) {
    out.push_back(static_cast<char>(SER::ARR));
    out.append((char *)&n, 4);
}

static void do_get(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup((HMap *)&g_data.db, &key.node, &entry_eq);
    if (!node) {
        return out_nil(out);
    }

    const std::string &val = getStructPtr(node)->val;
    out_str(out, val);
}

static void do_set(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node) {
        getStructPtr(node)->val.swap(cmd[2]);
    } else {
        Entry *ent = new Entry();
        ent->key.swap(key.key);
        ent->node.hcode = key.node.hcode;
        ent->val.swap(cmd[2]);
        hm_insert(&g_data.db, &ent->node);
    }
    return out_nil(out);
}

static void do_del(std::vector<std::string> &cmd, std::string &out) {
    Entry key;
    key.key.swap(cmd[1]);
    key.node.hcode = str_hash((uint8_t *)key.key.data(), key.key.size());

    HNode *node = hm_pop(&g_data.db, &key.node, &entry_eq);
    if (node) {
        delete getStructPtr(node);
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
    out_str(out, getStructPtr(node)->key);
}

static void do_keys(std::vector<std::string> &cmd, std::string &out) {
    (void)cmd;
    out_arr(out, (uint32_t)hm_size(&g_data.db));
    h_scan(&g_data.db.ht1, &cb_scan, &out);
    h_scan(&g_data.db.ht2, &cb_scan, &out);
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
    } else {
        // cmd is not recognized
        out_err(out, static_cast<uint32_t>(ERR::UNKNOWN), "Unknown cmd");
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
        out_err(out, static_cast<int32_t>(ERR::TOOBIG), "response is too big");
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
