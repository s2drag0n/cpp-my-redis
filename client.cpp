#include <arpa/inet.h>
#include <assert.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdint.h>
#include <string>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// static function can be only used in this file, so avoid same-name-issue
static int32_t send_req(int fd, const std::vector<std::string> &cmd);
static int32_t read_res(int fd);

const unsigned MAX_MSG_SIZE = 4096;

static void msg(const char *msg) { fprintf(stderr, "%s\n", msg); }

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket create error");
    }

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int rv = connect(fd, (sockaddr *)&addr, (socklen_t)sizeof(addr));
    if (rv < 0) {
        close(fd);
        die("connect error");
    }

    std::vector<std::string> cmd;
    for (int i = 1; i < argc; ++i) {
        cmd.push_back(argv[i]);
    }

    int32_t err = send_req(fd, cmd);
    if (err) {
        goto L_DONE;
    }

    err = read_res(fd);
    if (err) {
        goto L_DONE;
    }

L_DONE:
    close(fd);
    return 0;
}

static int32_t read_full(int fd, char *buf, size_t n) {
    while (n > 0) {
        size_t read_bytes = read(fd, buf, n);
        if (read_bytes > 0) {
            assert(read_bytes <= n);
            n -= read_bytes;
            buf += read_bytes;
        } else if (read_bytes == 0) {
            std::cout << "file EOF (here means clients droped this connection)"
                      << std::endl;
            return -1;
        } else if (read_bytes < 0 &&
                   ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
            std::cout
                << "happened when fd is set as nonblocking and fd is going to \
                blocking, this read function will be return right away"
                << std::endl;
            return -1;
        } else if (read_bytes < 0 && (errno == EINTR)) {
            std::cout << "the call was interrupted by a signal before any data "
                         "was read"
                      << std::endl;
            continue;
        } else {
            std::cout << "something else happened" << std::endl;
            return -1;
        }
    }
    return 0;
}

static int32_t write_full(int fd, char *buf, size_t n) {
    while (n > 0) {
        size_t write_bytes = write(fd, buf, n);
        if (write_bytes > 0) {
            assert(write_bytes <= n);
            n -= write_bytes;
            buf += write_bytes;
        } else if (write_bytes == 0) {
            std::cout << "write_byte is 0" << std::endl;
            return -1;
        } else if (write_bytes < 0 &&
                   ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
            std::cout
                << "happened when fd is set as nonblocking and fd is going to \
                blocking, this read function will be return right away"
                << std::endl;
            return -1;
        } else if (write_bytes < 0 && (errno == EINTR)) {
            std::cout << "the call was interrupted by a signal before any data "
                         "was read"
                      << std::endl;
            continue;
        } else {
            std::cout << "something else happened" << std::endl;
            return -1;
        }
    }
    return 0;
}

static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
    // send message
    uint32_t len = 4;
    for (const std::string &s : cmd) {
        len += 4 + s.size();
    }
    if (len > MAX_MSG_SIZE) {
        return -1;
    }

    char write_buf[4 + MAX_MSG_SIZE]{};
    memcpy(write_buf, &len, 4);
    uint32_t n = cmd.size();
    memcpy(&write_buf[4], &n, 4);
    size_t cur = 8;
    for (const std::string &s : cmd) {
        uint32_t p = (uint32_t)s.size();
        memcpy(&write_buf[cur], &p, 4);
        memcpy(&write_buf[cur + 4], s.data(), s.size());
        cur += 4 + s.size();
    }

    return write_full(fd, write_buf, 4 + len);
}

static int32_t read_res(int fd) {
    // recieve message
    char read_buf[4 + MAX_MSG_SIZE + 1]{};
    uint32_t err = read_full(fd, read_buf, 4);
    if (err) {
        if (errno == 0) {
            std::cout << "EOF" << std::endl;
        } else {
            std::cout << "read err" << std::endl;
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, read_buf, 4);
    if (len > MAX_MSG_SIZE) {
        std::cout << "too long" << std::endl;
        return -1;
    }

    err = read_full(fd, &read_buf[4], len);
    if (err) {
        if (errno == 0) {
            std::cout << "EOF" << std::endl;
        } else {
            std::cout << "read err" << std::endl;
        }
        return err;
    }

    // print the result
    uint32_t rescode = 0;
    if (len < 4) {
        msg("bad response");
        return -1;
    }

    memcpy(&rescode, &read_buf[4], 4);

    printf("server says: [%u] %.*s\n", rescode, len - 4, &read_buf[8]);

    return 0;
}
