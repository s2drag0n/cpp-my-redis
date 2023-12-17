#include <arpa/inet.h>
#include <assert.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

const unsigned MAX_MSG_SIZE = 4096;

const unsigned MAX_MSG_NUM = 1024;
const unsigned MAX_EVENTS = 1024;

static void msg(const char *msg) { fprintf(stderr, "%s\n", msg); }

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    exit(EXIT_FAILURE);
}

static void set_fd_nb(int fd) {
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

enum {
    STATE_REQ = 0,
    STATE_RES = 1,
    STATE_END = 2,
};

struct Conn {
    int fd = -1;
    uint32_t state = 0;
    // buffer for reading
    size_t read_buf_size = 0;
    uint8_t read_buf[4 + MAX_MSG_SIZE]{};
    // buffer for writing
    size_t write_buf_size = 0;
    size_t write_buf_sent = 0;
    uint8_t write_buf[4 + MAX_MSG_SIZE]{};
};

static void connection_io(Conn *conn);

static int accept_new_conn(std::map<int, Conn *> &, int);

int main() {
    int serv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_fd == -1) {
        die("socket create error");
    }

    struct sockaddr_in serv_addr {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(1234);
    int rv = inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr);
    if (rv <= 0) {
        die("IP address error");
    }

    rv = bind(serv_fd, (sockaddr *)&serv_addr, sizeof(serv_addr));
    if (rv == -1) {
        die("bind error");
    }

    rv = listen(serv_fd, SOMAXCONN);

    // a map of all client connections, keyed by fd
    std::map<int, Conn *> fd2conn;

    // set listen fd nb
    set_fd_nb(serv_fd);

    // use kqueue
    int kq = kqueue();
    if (kq == -1) {
        die("kqueue create error");
    }

    while (true) {
        struct kevent ev[MAX_MSG_NUM]{};

        int index = 0;
        EV_SET(&ev[index++], serv_fd, EVFILT_READ,
               EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
               (void *)(intptr_t)serv_fd);

        for (auto pair : fd2conn) {
            auto conn = pair.second;
            if (conn) {
                int flag =
                    (conn->state == STATE_REQ) ? EVFILT_READ : EVFILT_WRITE;
                EV_SET(&ev[index++], pair.first, flag,
                       EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
                       (void *)(intptr_t)pair.first);
            }
        }

        struct kevent activate_evs[MAX_EVENTS]{};
        int nfds = kevent(kq, ev, index, activate_evs, MAX_EVENTS, nullptr);
        if (nfds == -1) {
            die("kevent error");
        }

        for (int i = 0; i < nfds; ++i) {
            int fd = (intptr_t)activate_evs[i].udata;
            if (fd == serv_fd) {
                int clnt_fd = accept_new_conn(fd2conn, serv_fd);
                // int flag = (fd2conn[clnt_fd]->state == STATE_REQ) ?
                // EVFILT_READ : EVFILT_WRITE;
                EV_SET(&ev[index++], clnt_fd, EVFILT_READ,
                       EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
                       (void *)(intptr_t)clnt_fd);
            } else {
                Conn *conn = fd2conn[fd];
                if (conn) {
                    connection_io(conn);
                    if (conn->state == STATE_END) {
                        close(conn->fd);
                        fd2conn.erase(conn->fd);
                        free(conn);
                    }
                }
            }
            int events = activate_evs[i].filter;
        }
    }

    return 0;
}

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
    set_fd_nb(connfd);

    // create Conn struct
    struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));
    if (!conn) {
        msg("malloc error");
        close(connfd);
        return -1;
    }

    conn->fd = connfd;
    conn->state = STATE_REQ;
    conn->read_buf_size = 0;
    conn->write_buf_sent = 0;
    conn->write_buf_size = 0;

    // put conn in map
    fd2conn[connfd] = conn;
    return connfd;
}

static void state_req(Conn *conn);
static void state_res(Conn *conn);

static void connection_io(Conn *conn) {
    if (conn->state == STATE_REQ) {
        state_req(conn);
    } else if (conn->state == STATE_RES) {
        state_res(conn);
    } else {
        assert(0);
    }
}

static bool try_fill_buffer(Conn *conn);

// this state is for reading
static void state_req(Conn *conn) {
    while (try_fill_buffer(conn)) {
    }
}

static bool try_one_request(Conn *conn);
static bool try_fill_buffer(Conn *conn) {
    // tyr to fill the buff
    assert(conn->read_buf_size < sizeof(conn->read_buf));

    ssize_t rv = 0;
    do {
        size_t cap = sizeof(conn->read_buf) - conn->read_buf_size;
        rv = read(conn->fd, &conn->read_buf[conn->read_buf_size], cap);
    } while (rv < 0 && errno == EINTR);

    if (rv < 0 && (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        return false;
    }

    if (rv < 0) {
        msg("read error");
        conn->state = STATE_END;
        return false;
    }

    if (rv == 0) {
        if (conn->read_buf_size > 0) {
            msg("unexpected EOF");
        } else {
            msg("EOF");
        }
        conn->state = STATE_END;
        return false;
    }

    conn->read_buf_size += (size_t)rv;
    assert(conn->read_buf_size <= sizeof(conn->read_buf));

    // try to process requests one by one
    while (try_one_request(conn)) {
    }

    return (conn->state == STATE_REQ);
}

static uint32_t do_request(const uint8_t *req, uint32_t reqlen,
                           uint32_t *rescode, uint8_t *res, uint32_t *reslen);

static bool try_one_request(Conn *conn) {
    if (conn->read_buf_size < 4) {
        // not enough data in the buffer
        return false;
    }

    uint32_t len = 0;
    memcpy(&len, &conn->read_buf[0], 4);
    if (len > MAX_MSG_SIZE) {
        msg("too long");
        conn->state = STATE_END;
        return false;
    }
    if (4 + len > conn->read_buf_size) {
        // not enough data inthe buffer, try next iteration
        return false;
    }

    // got one request, do somthing with it;
    /* std::cout << "client says : " << &conn->read_buf[4] << std::endl; */

    // generate echoing response
    uint32_t rescode = 0;
    uint32_t wlen = 0;
    uint32_t err = do_request(&conn->read_buf[4], len, &rescode,
                              &conn->write_buf[4 + 4], &wlen);
    if (err) {
        conn->state = STATE_END;
        return false;
    }
    wlen += 4;

    memcpy(conn->write_buf, &wlen, 4);
    memcpy(&conn->write_buf[4], &rescode, 4);
    conn->write_buf_size = 4 + wlen;

    // remove the request from the read buffer.
    // note: frequent memmove is inefficient.
    // note: need better handing for production code.

    size_t remain = conn->read_buf_size - 4 - len;
    if (remain) {
        memmove(conn->read_buf, &conn->read_buf[4 + len], remain);
    }
    conn->read_buf_size = remain;

    // change state.
    conn->state = STATE_RES;
    state_res(conn);

    // continue the outer loop if the request was fully processed.
    return (conn->state == STATE_REQ);
}

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

enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
};

static std::map<std::string, std::string> g_map;

static uint32_t do_get(const std::vector<std::string> &cmd, uint8_t *res,
                       uint32_t *reslen) {
    if (!g_map.count(cmd[1])) {
        return RES_NX;
    }

    std::string &val = g_map[cmd[1]];
    assert(val.size() < MAX_MSG_SIZE);
    memcpy(res, val.data(), val.size());
    *reslen = (uint32_t)val.size();
    return RES_OK;
}
static uint32_t do_set(const std::vector<std::string> &cmd, uint8_t *res,
                       uint32_t *reslen) {
    (void)res;
    (void)reslen;
    g_map[cmd[1]] = cmd[2];
    return RES_OK;
}

static uint32_t do_del(const std::vector<std::string> &cmd, uint8_t *res,
                       uint32_t *reslen) {
    (void)res;
    (void)reslen;
    g_map.erase(cmd[1]);
    return RES_OK;
}

static bool cmd_is(const std::string &word, const char *cmd) {
    return 0 == strcasecmp(word.c_str(), cmd);
}

static uint32_t do_request(const uint8_t *req, uint32_t reqlen,
                           uint32_t *rescode, uint8_t *res, uint32_t *reslen) {
    std::vector<std::string> cmd;
    if (0 != parse_req(req, reqlen, cmd)) {
        msg("bad req");
        return -1;
    }

    if (cmd.size() == 2 && cmd_is(cmd[0], "get")) {
        *rescode = do_get(cmd, res, reslen);
    } else if (cmd.size() == 3 && cmd_is(cmd[0], "set")) {
        *rescode = do_set(cmd, res, reslen);
    } else if (cmd.size() == 2 && cmd_is(cmd[0], "del")) {
        *rescode = do_del(cmd, res, reslen);
    } else {
        *rescode = RES_ERR;
        const char *msg = "Unknown cmd";
        strcpy((char *)res, msg);
        *reslen = strlen(msg);
        return 0;
    }
    return 0;
}

static bool try_flush_buffer(Conn *conn);

static void state_res(Conn *conn) {
    while (try_flush_buffer(conn)) {
    }
}

static bool try_flush_buffer(Conn *conn) {
    ssize_t rv = 0;
    do {
        size_t remain = conn->write_buf_size - conn->write_buf_sent;
        rv = write(conn->fd, &conn->write_buf[conn->write_buf_sent], remain);
    } while (rv < 0 && errno == EAGAIN);

    if (rv < 0 && errno == EINTR) {
        return false;
    }
    if (rv < 0) {
        msg("write error");
        conn->state = STATE_END;
        return false;
    }

    conn->write_buf_sent += (size_t)rv;
    assert(conn->write_buf_sent <= conn->write_buf_size);

    if (conn->write_buf_sent == conn->write_buf_size) {
        // reponse was fully sent, change state back.
        conn->state = STATE_REQ;
        conn->write_buf_sent = 0;
        conn->write_buf_size = 0;
        return false;
    }

    // still got some data in write buffer, could try write again.
    return true;
}
