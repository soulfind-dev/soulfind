// SPDX-FileCopyrightText: 2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.select;
@safe:

import core.time : Duration;
import std.socket : socket_t;

enum SelectEvent
{
    read   = 1 << 0,
    write  = 1 << 1
}

class Selector
{
    private Duration               timeout;
    private SelectEvent[socket_t]  fd_events;

    this(Duration timeout)
    {
        this.timeout = timeout;
    }

    abstract void register(socket_t fd, SelectEvent events);
    abstract void unregister(socket_t fd, SelectEvent events);
    abstract SelectEvent[socket_t] select();
}

version (linux) final class EpollSelector : Selector
{
    import core.sys.linux.epoll;
    import core.sys.posix.unistd : close;

    private int            epoll_fd;
    private epoll_event[]  epoll_events;
    private size_t         max_events;

    this(Duration timeout)
    {
        super(timeout);
        epoll_fd = create_epoll();
    }

    ~this()
    {
        close(epoll_fd);
    }

    override void register(socket_t fd, SelectEvent events)
    {
        const is_registered = fd in fd_events;
        if (is_registered && (fd_events[fd] & events) == events)
            return;

        auto event = create_epoll_event(fd, events);
        auto op = EPOLL_CTL_MOD;

        if (!is_registered) {
            op = EPOLL_CTL_ADD;
            max_events++;
            if (epoll_events.length < max_events)
                epoll_events.length = max_events;
        }

        fd_events[fd] |= events;
        control(op, fd, event);
    }

    override void unregister(socket_t fd, SelectEvent events)
    {
        if (fd !in fd_events || (fd_events[fd] & events) == 0)
            return;

        fd_events[fd] &= ~events;
        const remaining_events = fd_events[fd];
        auto event = create_epoll_event(fd, remaining_events);

        if (remaining_events == 0) {
            control(EPOLL_CTL_DEL, fd, event);
            fd_events.remove(fd);
            return;
        }
        control(EPOLL_CTL_MOD, fd, event);
    }

    override SelectEvent[socket_t] select()
    {
        SelectEvent[socket_t] ready_fds;
        const num_fds = wait();

        if (num_fds > 0) foreach (n; 0 .. num_fds) {
            const ev = epoll_events[n];
            const fd = cast(socket_t) ev.data.fd;

            if (ev.events & (EPOLLIN | EPOLLERR | EPOLLHUP))
                ready_fds[fd] |= SelectEvent.read;

            if (ev.events & EPOLLOUT)
                ready_fds[fd] |= SelectEvent.write;
        }
        return ready_fds;
    }

    private epoll_event create_epoll_event(socket_t fd, SelectEvent events)
    {
        epoll_event event;
        if (events == 0)
            return event;

        event.data.fd = fd;
        if (events & SelectEvent.read)  event.events |= EPOLLIN;
        if (events & SelectEvent.write) event.events |= EPOLLOUT;

        return event;
    }

    @trusted
    private int create_epoll()
    {
        return epoll_create1(EPOLL_CLOEXEC);
    }

    @trusted
    private void control(int op, socket_t fd, epoll_event event)
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

final class PollSelector : Selector
{
    version (Windows) {
        import core.sys.windows.winsock2 : poll = WSAPoll, POLLERR,
                                           pollfd = WSAPOLLFD, POLLHUP,
                                           POLLIN = POLLRDNORM,
                                           POLLOUT = POLLWRNORM;
    }
    else version (Posix) {
        import core.sys.posix.poll;
    }

    private SelectEvent[socket_t]  fd_events;
    private pollfd[]               pollfds;

    this(Duration timeout)
    {
        super(timeout);
    }

    override void register(socket_t fd, SelectEvent events)
    {
        const is_registered = fd in fd_events;
        if (is_registered && (fd_events[fd] & events) == events)
            return;

        const pfd = create_pollfd(fd, events);

        if (is_registered)
            pollfds[find_fd_idx(fd)] = pfd;
        else
            pollfds ~= pfd;

        fd_events[fd] |= events;
    }

    override void unregister(socket_t fd, SelectEvent events)
    {
        if (fd !in fd_events || (fd_events[fd] & events) == 0)
            return;

        fd_events[fd] &= ~events;
        const remaining_events = fd_events[fd];
        size_t idx = find_fd_idx(fd);

        if (remaining_events == 0) {
            fd_events.remove(fd);
            pollfds[idx] = pollfds[$ - 1];
            pollfds.length--;
            return;
        }
        pollfds[idx] = create_pollfd(fd, remaining_events);
    }

    override SelectEvent[socket_t] select()
    {
        SelectEvent[socket_t] ready_fds;
        const num_fds = wait();

        if (num_fds > 0) foreach (ref pfd; pollfds) {
            if (pfd.revents == 0)
                continue;

            const fd = cast(socket_t) pfd.fd;

            if (pfd.revents & (POLLIN | POLLERR | POLLHUP))
                ready_fds[fd] |= SelectEvent.read;

            if (pfd.revents & POLLOUT)
                ready_fds[fd] |= SelectEvent.write;
        }
        return ready_fds;
    }

    private pollfd create_pollfd(socket_t fd, SelectEvent events)
    {
        pollfd pfd;
        pfd.fd = fd;
        if (events & SelectEvent.read)  pfd.events |= POLLIN;
        if (events & SelectEvent.write) pfd.events |= POLLOUT;

        return pfd;
    }

    private size_t find_fd_idx(socket_t fd)
    {
        foreach (i, ref pfd; pollfds)
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
    alias DefaultSelector = EpollSelector;
else
    alias DefaultSelector = PollSelector;
