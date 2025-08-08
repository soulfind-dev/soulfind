// SPDX-FileCopyrightText: 2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.select;
@safe:

import core.time : Duration;
import std.socket : Socket, SocketSet;

enum SelectEvent
{
    read   = 1 << 0,
    write  = 1 << 1
}

version (linux) struct EpollSelector
{
    import core.sys.linux.epoll : epoll_create1, epoll_ctl, EPOLL_CTL_ADD,
                                  EPOLL_CTL_DEL, EPOLL_CTL_MOD, epoll_event,
                                  epoll_wait, EPOLLERR, EPOLLHUP, EPOLLIN,
                                  EPOLLOUT;
    import core.sys.posix.unistd : close;

    private Duration             timeout;
    private int                  epoll_fd;
    private epoll_event[]        epoll_events;
    private SelectEvent[Socket]  socks;
    private Socket[int]          fd_socks;

    this(Duration timeout)
    {
        this.timeout = timeout;
        epoll_fd = create();
    }
    @disable this();

    ~this()
    {
        close(epoll_fd);
    }

    void register(Socket sock, SelectEvent events)
    {
        if (sock in socks && (socks[sock] & events) == events)
            return;

        const fd = cast(int) sock.handle;
        auto op = EPOLL_CTL_MOD;

        if (fd !in fd_socks) {
            fd_socks[fd] = sock;
            op = EPOLL_CTL_ADD;
            epoll_events.length = fd_socks.length;
        }

        socks[sock] |= events;

        epoll_event new_event;
        new_event.data.fd = fd;
        if (events & SelectEvent.read) new_event.events |= EPOLLIN;
        if (events & SelectEvent.write) new_event.events |= EPOLLOUT;

        ctl(op, fd, new_event);
    }

    void unregister(Socket sock, SelectEvent events)
    {
        if (sock !in socks || (socks[sock] & events) == 0)
            return;

        socks[sock] &= ~events;
        const fd = cast(int) sock.handle;
        const remaining_events = socks[sock];
        epoll_event new_event;

        if (remaining_events == 0) {
            ctl(EPOLL_CTL_DEL, fd, new_event);
            fd_socks.remove(fd);
            socks.remove(sock);
            epoll_events.length = fd_socks.length;
            return;
        }

        new_event.data.fd = fd;
        if (remaining_events & SelectEvent.read) new_event.events |= EPOLLIN;
        if (remaining_events & SelectEvent.write) new_event.events |= EPOLLOUT;

        ctl(EPOLL_CTL_MOD, fd, new_event);
    }

    SelectEvent[Socket] select()
    {
        SelectEvent[Socket] ready_socks;
        const num_fds = wait();

        if (num_fds > 0) foreach (n; 0 .. num_fds) {
            auto ev = epoll_events[n];
            auto sock = fd_socks[ev.data.fd];

            if (ev.events & (EPOLLIN | EPOLLERR | EPOLLHUP))
                ready_socks[sock] |= SelectEvent.read;

            if (ev.events & EPOLLOUT)
                ready_socks[sock] |= SelectEvent.write;
        }
        return ready_socks;
    }

    @trusted
    private int create()
    {
        const SOCK_CLOEXEC = 0x80000;
        return epoll_create1(SOCK_CLOEXEC);
    }

    @trusted
    private void ctl(int op, int fd, epoll_event event)
    {
        epoll_ctl(epoll_fd, op, fd, &event);
    }

    @trusted
    private int wait()
    {
        return epoll_wait(
            epoll_fd, epoll_events.ptr, cast(int) epoll_events.length,
            cast(int) timeout.total!"msecs"
        );
    }
}

struct PollSelector
{
    version (Windows) {
        import core.sys.windows.winsock2 : poll = WSAPoll, POLLERR,
                                           pollfd = WSAPOLLFD, POLLHUP,
                                           POLLIN = POLLRDNORM,
                                           POLLOUT = POLLWRNORM;
    }
    else version (Posix) {
        import core.sys.posix.poll : poll, POLLERR, pollfd, POLLHUP, POLLIN,
                                     POLLOUT;
    }

    private Duration timeout;
    private SelectEvent[Socket] socks;
    private Socket[size_t] fd_socks;
    private pollfd[] pollfds;

    this(Duration timeout)
    {
        this.timeout = timeout;
    }
    @disable this();

    void register(Socket sock, SelectEvent events)
    {
        if (sock in socks && (socks[sock] & events) == events)
            return;

        const fd = cast(int) sock.handle;
        const pfd = create_pollfd(fd, events);
        const exists = fd in fd_socks;

        if (!exists) fd_socks[fd] = sock;
        socks[sock] |= events;

        if (exists)
            pollfds[find_fd_idx(fd)] = pfd;
        else
            pollfds ~= pfd;
    }

    void unregister(Socket sock, SelectEvent events)
    {
        if (sock !in socks || (socks[sock] & events) == 0)
            return;

        const fd = cast(int) sock.handle;
        size_t idx = find_fd_idx(fd);

        socks[sock] &= ~events;
        const remaining_events = socks[sock];

        if (remaining_events == 0) {
            socks.remove(sock);
            fd_socks.remove(fd);
            pollfds[idx] = pollfds[$ - 1];
            pollfds.length--;
            return;
        }
        pollfds[idx] = create_pollfd(fd, remaining_events);
    }

    SelectEvent[Socket] select()
    {
        SelectEvent[Socket] ready_socks;
        const num_fds = wait();

        if (num_fds > 0) foreach (pfd; pollfds) {
            if (pfd.revents == 0)
                continue;

            auto sock = fd_socks[pfd.fd];

            if (pfd.revents & (POLLIN | POLLERR | POLLHUP))
                ready_socks[sock] |= SelectEvent.read;

            if (pfd.revents & POLLOUT)
                ready_socks[sock] |= SelectEvent.write;
        }
        return ready_socks;
    }

    private pollfd create_pollfd(int fd, SelectEvent events)
    {
        pollfd pfd;
        pfd.fd = fd;
        if (events & SelectEvent.read) pfd.events |= POLLIN;
        if (events & SelectEvent.write) pfd.events |= POLLOUT;

        return pfd;
    }

    private size_t find_fd_idx(int fd)
    {
        foreach (i, pfd; pollfds)
            if (pfd.fd == fd)
                return i;
        return size_t.max;
    }

    @trusted
    private int wait()
    {
        return poll(
            pollfds.ptr, cast(uint) pollfds.length,
            cast(int) timeout.total!"msecs"
        );
    }
}

version (linux)
    alias Selector = EpollSelector;
else
    alias Selector = PollSelector;
