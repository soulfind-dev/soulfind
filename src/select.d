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

    @trusted
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

struct SelectSelector
{
    private Duration             timeout;
    private SelectEvent[Socket]  socks;
    private SocketSet            read_set;
    private SocketSet            write_set;

    @trusted
    this(Duration timeout)
    {
        this.timeout = timeout;
        read_set = new SocketSet();
        write_set = new SocketSet();
    }
    @disable this();

    void register(Socket sock, SelectEvent events)
    {
        if (sock in socks && (socks[sock] & events) == events)
            return;

        socks[sock] |= events;

        if (events & SelectEvent.read)
            read_set.add(sock);

        if (events & SelectEvent.write)
            write_set.add(sock);
    }

    void unregister(Socket sock, SelectEvent events)
    {
        if (sock !in socks)
            return;

        if ((socks[sock] & events) == 0)
            return;

        socks[sock] &= ~events;
        const remaining_events = socks[sock];

        if (remaining_events & SelectEvent.read)
            read_set.add(sock);
        else
            read_set.remove(sock);

        if (remaining_events & SelectEvent.write)
            write_set.add(sock);
        else
            write_set.remove(sock);

        if (remaining_events == 0)
            socks.remove(sock);
    }

    SelectEvent[Socket] select()
    {
        SelectEvent[Socket] ready_socks;
        Socket.select(read_set, write_set, null, timeout);

        foreach (sock, events; socks) {
            if (read_set.isSet(sock))
                ready_socks[sock] |= SelectEvent.read;
            else
                read_set.add(sock);

            if (write_set.isSet(sock))
                ready_socks[sock] |= SelectEvent.write;
            else
                write_set.add(sock);
        }
        return ready_socks;
    }
}

version (linux)
    alias Selector = EpollSelector;
else
    alias Selector = SelectSelector;
