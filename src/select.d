// SPDX-FileCopyrightText: 2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.select;
@safe:

import std.datetime : Duration;
import std.socket : socket_t;

version (linux)         version = epoll;
version (OSX)           version = kqueue;
version (FreeBSD)       version = kqueue;
version (NetBSD)        version = kqueue;
version (DragonFlyBSD)  version = kqueue;


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

version (epoll) final class EpollSelector : Selector
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
            const event = epoll_events[n];
            const fd = cast(socket_t) event.data.fd;

            if (event.events & (EPOLLIN | EPOLLERR | EPOLLHUP))
                ready_fds[fd] |= SelectEvent.read;

            if (event.events & EPOLLOUT)
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

version (kqueue) final class KqueueSelector : Selector
{
    version      (OSX)           import core.sys.darwin.sys.event;
    else version (FreeBSD)       import core.sys.freebsd.sys.event;
    else version (NetBSD)        import core.sys.netbsd.sys.event;
    else version (DragonFlyBSD)  import core.sys.dragonflybsd.sys.event;
    import core.sys.posix.time : time_t, timespec;
    import core.sys.posix.unistd : close;

    private int         kqueue_fd;
    private kevent_t[]  kevents;
    private size_t      max_events;

    this(Duration timeout)
    {
        super(timeout);
        kqueue_fd = create_kqueue();
    }

    ~this()
    {
        close(kqueue_fd);
    }

    override void register(socket_t fd, SelectEvent events)
    {
        if (fd in fd_events && (fd_events[fd] & events) == events)
            return;

        kevent_t[2] changes;
        size_t num_changes;

        if (events & SelectEvent.read)
            changes[num_changes++] = kevent_t(fd, EVFILT_READ, EV_ADD);

        if (events & SelectEvent.write)
            changes[num_changes++] = kevent_t(fd, EVFILT_WRITE, EV_ADD);

        max_events += num_changes;
        if (kevents.length < max_events)
            kevents.length = max_events;

        fd_events[fd] |= events;
        control(changes[0 .. num_changes]);
    }

    override void unregister(socket_t fd, SelectEvent events)
    {
        if (fd !in fd_events)
            return;

        const deleted_events = fd_events[fd] & events;
        if (deleted_events == 0)
            return;

        fd_events[fd] &= ~deleted_events;
        kevent_t[2] changes;
        size_t num_changes;

        if (deleted_events & SelectEvent.read)
            changes[num_changes++] = kevent_t(fd, EVFILT_READ, EV_DELETE);

        if (deleted_events & SelectEvent.write)
            changes[num_changes++] = kevent_t(fd, EVFILT_WRITE, EV_DELETE);

        max_events -= num_changes;
        control(changes[0 .. num_changes]);
    }

    override SelectEvent[socket_t] select()
    {
        SelectEvent[socket_t] ready_fds;
        const num_fds = wait();

        if (num_fds > 0) foreach (n; 0 .. num_fds) {
            const event = kevents[n];
            const fd = cast(socket_t) event.ident;

            if (event.filter == EVFILT_READ)
                ready_fds[fd] |= SelectEvent.read;

            if (event.filter == EVFILT_WRITE)
                ready_fds[fd] |= SelectEvent.write;
        }
        return ready_fds;
    }

    @trusted
    private int create_kqueue()
    {
        return kqueue();
    }

    @trusted
    private void control(kevent_t[] changes)
    {
        kevent(
            kqueue_fd, changes.ptr, cast(int) changes.length, null, 0, null
        );
    }

    @trusted
    private int wait()
    {
        timespec spec;
        timeout.split!("seconds", "nsecs")(spec.tv_sec, spec.tv_nsec);

        return kevent(
            kqueue_fd, null, 0, kevents.ptr, cast(int) kevents.length, &spec
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

version      (epoll)   alias DefaultSelector = EpollSelector;
else version (kqueue)  alias DefaultSelector = KqueueSelector;
else                   alias DefaultSelector = PollSelector;
