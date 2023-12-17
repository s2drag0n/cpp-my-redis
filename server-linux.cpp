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
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
// #include <vector>

const unsigned MAX_MSG_SIZE = 4096;

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

  // the event loop
  // std::vector<struct pollfd> poll_args;
  struct epoll_event ev = {}, events[MAX_EVENTS]{};
  int epfd = epoll_create1(0);
  if (epfd == -1) {
    die("epoll create error");
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = serv_fd;

  rv = epoll_ctl(epfd, EPOLL_CTL_ADD, serv_fd, &ev);
  if (rv == -1) {
    die("epoll ctl error");
  }

  while (true) {
    // for (auto pair : fd2conn) {
    //     if (!pair.second) {
    //         msg("qqq");
    //         continue;
    //     }
    //     ev.events =
    //         ((pair.second->state == STATE_REQ) ? EPOLLIN : EPOLLOUT) |
    //         EPOLLET;
    //     ev.data.fd = pair.first;
    //     rv = epoll_ctl(epfd, EPOLL_CTL_ADD, pair.first, &ev);
    //     if (rv == -1) {
    //         die("epoll add error");
    //     }
    // }
    bzero(events, MAX_EVENTS * sizeof(events[0]));
    int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      die("epoll error");
    }

    for (int i = 0; i < nfds; ++i) {
      if (events[i].data.fd == serv_fd) {
        int clnt_fd = accept_new_conn(fd2conn, serv_fd);
        ev.events =
            ((fd2conn[clnt_fd]->state == STATE_REQ) ? EPOLLIN : EPOLLOUT) |
            EPOLLET;
        ev.data.flash.nvimfd = clnt_fd;
        rv = epoll_ctl(epfd, EPOLL_CTL_ADD, clnt_fd, &ev);
        if (rv == -1) {
          die("epoll add error");
        }
      } else {
        Conn *conn = fd2conn[events[i].data.fd];
        connection_io(conn);
        if (conn->state == STATE_END) {
          close(conn->fd);
          fd2conn.erase(conn->fd);
          free(conn);
        }
      }
    }
    // poll_args.clear();

    // // listening fd is put in the first positon
    // struct pollfd serv_pfd = {serv_fd, POLLIN, 0};
    // poll_args.emplace_back(serv_pfd);

    // // connection fds
    // for (auto &pair : fd2conn) {
    //     Conn *conn = pair.second;
    //     if (!conn) {
    //         continue;
    //     }

    //     struct pollfd clnt_pfd {};
    //     clnt_pfd.fd = conn->fd;
    //     clnt_pfd.events = (conn->state == STATE_REQ) ? POLLIN : POLLOUT;
    //     clnt_pfd.events |= POLLERR;
    //     poll_args.emplace_back(clnt_pfd);
    // }

    // // poll for active fds
    // rv = poll(poll_args.data(), poll_args.size(), 1000);
    // if (rv < 0) {
    //     die("poll error");
    // }

    // // process active connections
    // for (int i = 1; i < poll_args.size(); ++i) {
    //     if (poll_args[i].revents) {
    //         Conn *conn = fd2conn[poll_args[i].fd];
    //         connection_io(conn);
    //         if (conn->state == STATE_END) {
    //             // client closed normally or something bad happened
    //             // destroy the connection
    //             fd2conn.erase(conn->fd);
    //             close(conn->fd);
    //             free(conn);
    //         }
    //     }
    // }

    // try to accept a new connection if the listening fd is active
    // if (poll_args[0].revents) {
    //     accept_new_conn(fd2conn, serv_fd);
    // }
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

  if (rv < 0 && errno == EAGAIN) {
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
static bool try_one_request(Conn *conn) {
  if (conn->read_buf_size < 4) {
    // not enough data in the buffer
    return false;
  }

  uint32_t len = 0;
  if (len > MAX_MSG_SIZE) {
    msg("too long");
    conn->state = STATE_END;
    return false;
    if (4 + len > conn->read_buf_size) {
      // not enough data inthe buffer, try next iteration
      return false;
    }

    // got one request, do somthing with it;
    std::cout << "client says : " << &conn->read_buf[4] << std::endl;

    // generate echoing response
    memcpy(conn->write_buf, &len, 4);
    memcpy(&conn->write_buf[4], &conn->read_buf[4], len);
    conn->write_buf_size = 4 + len;

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

  static bool try_flush_buffer(Conn * conn);

  static void state_res(Conn * conn) {
    while (try_flush_buffer(conn)) {
    }
  }

  static bool try_flush_buffer(Conn * conn) {
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
