#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/_types/_socklen_t.h>
#include <sys/_types/_ssize_t.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static void msg(const char *msg) { std::cerr << msg << std::endl; }

static void die(const char *msg) {
    int err = errno;
    std::cerr << "[" << err << "] " << msg << std::endl;
    exit(EXIT_FAILURE);
}

static int32_t read_full(int fd, char *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = read(fd, buf, n);
        if (rv <= 0) {
            return -1;
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0) {
            return -1;
        }

        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

const size_t MAX_MSG_LEN = 4096;

static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
    /*
     * one request is made like this
     * --len--size--cmdlen1--cmd1--cmdlen2--cmd2--...
     * --4----4-----4--------len1--4--------len2-...
     * */
    int32_t len = 4;
    for (const std::string &s : cmd) {
        len += 4 + s.size();
    }

    if (len > MAX_MSG_LEN) {
        return -1;
    }

    char wbuf[4 + MAX_MSG_LEN]{};
    memcpy(&wbuf[0], &len, 4);
    uint32_t n = cmd.size();
    memcpy(&wbuf[4], &n, 4);
    size_t cur = 8;
    for (const std::string &s : cmd) {
        uint32_t p = (uint32_t)s.size();
        memcpy(&wbuf[cur], &p, 4);
        memcpy(&wbuf[cur + 4], s.data(), s.size());
        cur += 4 + s.size();
    }
    return write_all(fd, wbuf, 4 + len);
}

enum class SER { NIL, ERR, STR, INT, ARR };

static int32_t on_response(const uint8_t *data, size_t size) {
    /*
     * except a 4 bytes lenth of msg,
     * response msg is made like this
     *
     * SER::NIL
     * --SER--
     * --1----
     *
     * SER::ERR
     * --SER--code--msglen--msg--
     * --1----4-----4-------len--
     *
     * SER::STR
     * --SER--strlen--str--
     * --1----4-------len--
     *
     * SER::INT
     * --SER--int64--
     * --1----8-----
     *
     * SER::ARR : maybe several response msg in hide in the ARR msg
     * --SER--responselen--response--
     * --1----4------------len
     *
     * */
    if (size < 1) {
        msg("bad response");
        return -1;
    }

    switch (static_cast<SER>(data[0])) {
    case SER::NIL:
        std::cout << "(nil)" << std::endl;
        return 1;
    case SER::ERR:
        if (size < 1 + 8) {
            msg("bad response");
            return -1;
        }
        {
            int32_t code = 0;
            uint32_t len = 0;
            memcpy(&code, &data[1], 4);
            if (size < 1 + 8 + len) {
                msg("bad response");
                return -1;
            }

            std::cout << "(err) " << code << " " << std::setw(len)
                      << std::setfill(' ') << &data[1 + 8] << std::endl;
            return 1 + 8 + len;
        }
    case SER::STR:
        if (size < 1 + 4) {
            msg("bad response");
            return -1;
        }
        {
            uint32_t len = 0;
            memcpy(&len, &data[1], 4);
            if (size < 1 + 4 + len) {
                msg("bad response");
                return -1;
            }
            std::cout << "(str) " << std::setw(len) << std::setfill(' ')
                      << &data[1 + 4] << std::endl;
            return 1 + 4 + len;
        }
    case SER::INT:
        if (size < 1 + 8) {
            msg("bad response");
            return -1;
        }
        {
            int64_t val = 0;
            memcpy(&val, &data[1], 8);
            std::cout << "(int) " << val << std::endl;
            return 1 + 8;
        }
    case SER::ARR:
        if (size < 1 + 4) {
            msg("bad response");
            return -1;
        }
        {
            uint32_t len = 0;
            memcpy(&len, &data[1], 4);
            std::cout << "(arr) len=" << len << std::endl;
            size_t arr_bytes = 1 + 4;
            for (size_t i = 0; i < len; ++i) {
                int32_t rv = on_response(&data[arr_bytes], size - arr_bytes);
                if (rv < 0) {
                    return rv;
                }
                arr_bytes += (size_t)rv;
            }
            std::cout << "(arr) end" << std::endl;
            return (int32_t)arr_bytes;
        }
    default:
        msg("bad response");
        return -1;
    }
}

static int32_t read_res(int fd) {
    // 4 bytes header
    char rbuf[4 + MAX_MSG_LEN + 1]{};
    errno = 0;
    int32_t err = read_full(fd, rbuf, 4);
    if (err) {
        if (errno == 0) {
            msg("EOF");
        } else {
            msg("read error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf, 4); // assume little endian
    if (len > MAX_MSG_LEN) {
        msg("too long");
        return -1;
    }

    // reply body
    err = read_full(fd, &rbuf[4], len);
    if (err) {
        msg("read error");
        return err;
    }

    // print the result
    int32_t rv = on_response((uint8_t *)&rbuf[4], len);
    if (rv > 0 and (uint32_t) rv != len) {
        msg("bad response");
        rv = -1;
    }

    return rv;
}

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket create error");
    }

    struct sockaddr_in serv_addr {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(1234);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr.s_addr);

    int rv = connect(fd, (sockaddr *)&serv_addr, (socklen_t)sizeof(serv_addr));
    if (rv < 0) {
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
