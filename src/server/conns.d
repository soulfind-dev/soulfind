// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.conns;
@safe:

import soulfind.defines : blue, bold, check_user_interval, conn_backlog_length,
                          log_msg, log_user, max_msg_size, norm, red, VERSION;
import soulfind.pwhash : process_password_tasks;
import soulfind.select : DefaultSelector, SelectEvent, Selector;
import soulfind.server.messages : SMessage;
import soulfind.server.msghandler : MessageHandler;
import soulfind.server.server : Server;
import soulfind.server.user : User;
import std.bitmanip : Endian, nativeToLittleEndian, peek, read;
import std.datetime : MonoTime, msecs;
import std.socket : InternetAddress, Socket, socket_t, SocketAcceptException,
                    SocketOption, SocketOptionLevel, SocketOSException,
                    SocketShutdown, TcpSocket;
import std.stdio : writeln;

const enum Logging : uint
{
    disabled  = 0,
    all       = 1,
    redacted  = 2
}

final class UserConnections
{
    private Server          server;
    private Selector        selector;
    private MessageHandler  msg_handler;
    private User[socket_t]  sock_users;
    private MonoTime        last_user_check;


    this(Server server)
    {
        this.server       = server;
        this.selector     = new DefaultSelector(100.msecs);
        this.msg_handler  = new MessageHandler(server);
    }

    bool listen(ushort port)
    {
        writeln(
            red, "\&hearts;", norm, " ", bold, "Soulfind", " ", VERSION,
            norm, " process ", process_id, " listening on port ", port
        );

        auto listen_sock = create_listen_sock(port);
        if (listen_sock is null)
            return false;

        version (unittest)
            const running = true;
        else
            import soulfind.main : running;

        while (running) {
            const ready_fds = selector.select();

            // Process ready sockets
            foreach (ready_fd ; ready_fds) {
                const recv_ready = (ready_fd.events & SelectEvent.read) != 0;
                const send_ready = (ready_fd.events & SelectEvent.write) != 0;

                if (ready_fd.fd == listen_sock.handle) {
                    if (recv_ready) accept(listen_sock);
                    continue;
                }

                auto user = sock_users[ready_fd.fd];
                user.handle_io_events(recv_ready, send_ready);
            }

            // Handle orphaned, unauthenticated and banned users
            const curr_time = MonoTime.currTime;
            if ((curr_time - last_user_check) >= check_user_interval) {
                foreach (ref user ; sock_users.dup) {
                    const orphaned = user.disconnect_orphan();
                    if (orphaned)
                        continue;

                    const unauthenticated = user.disconnect_unauthenticated();
                    if (unauthenticated)
                        continue;

                    const banned = user.disconnect_banned();
                    if (banned)
                        continue;

                    user.refresh_privileges();
                }
                server.refresh_search_filters();
                server.refresh_unsearchable_users();
                last_user_check = curr_time;
            }

            // Password hashing in thread/task pool, process results
            process_password_tasks();
        }

        // Clean up connections
        foreach (ref user ; sock_users.dup)
            user.disconnect();

        return true;
    }

    void close_connection(UserConnection conn)
    {
        if (conn.sock is null)
            return;

        const sock_handle = conn.sock.handle;
        if (sock_handle in sock_users) {
            if (log_user) writeln(
                "Closing connection to user ", sock_users[sock_handle].username
            );
            sock_users.remove(sock_handle);
        }
        conn.close();
    }

    @trusted
    private size_t process_id () {
        version (Windows)
            import core.sys.windows.winbase : getpid = GetCurrentProcessId;
        else version (Posix)
            import core.sys.posix.unistd : getpid;
        return getpid;
    }

    private Socket create_listen_sock(ushort port)
    {
        auto listen_sock = new TcpSocket();
        listen_sock.blocking = false;

        version (Posix)
            listen_sock.setOption(
                SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);

        try {
            auto listen_address = new InternetAddress(port);
            listen_sock.bind(listen_address);
            listen_sock.listen(conn_backlog_length);
        }
        catch (SocketOSException e) {
            const min_port = 1024;
            writeln("Unable to bind socket to port ", port);
            if (port < min_port) writeln(
                "Are you trying to use a port less than ", min_port,
                " while running as a user?"
            );
            return null;
        }

        selector.register(listen_sock.handle, SelectEvent.read);
        return listen_sock;
    }

    private void accept(Socket listen_sock)
    {
        while (true) {
            Socket sock;
            try
                sock = listen_sock.accept();
            catch (SocketAcceptException)
                break;

            if (!sock.isAlive)
                break;

            if (log_user) writeln("Connection attempt accepted");

            sock_users[sock.handle] = new User(
                server, new UserConnection(sock, selector, msg_handler)
            );
        }
    }
}

final class UserConnection
{
    const MonoTime          created_monotime;
    const InternetAddress   address;

    private Socket          sock;
    private Selector        selector;
    private MessageHandler  msg_handler;

    private ubyte[]         in_buf;
    private long            in_msg_size = -1;
    private ubyte[]         out_buf;


    this(Socket sock, Selector selector, MessageHandler msg_handler)
    {
        this.sock              = sock;
        this.selector          = selector;
        this.msg_handler       = msg_handler;
        this.created_monotime  = MonoTime.currTime;
        this.address           = cast(InternetAddress) sock.remoteAddress;

        setup_socket();
    }


    bool is_sending()
    {
        return out_buf.length > 0;
    }

    bool send_buffer()
    {
        const send_len = sock.send(out_buf);
        if (send_len == Socket.ERROR)
            return false;

        out_buf = out_buf[send_len .. $];

        if (!is_sending)
            selector.unregister(sock.handle, SelectEvent.write);

        return true;
    }

    void send_message(Logging log = Logging.all)(scope SMessage msg,
                                                 string target_username)
    {
        const msg_buf = msg.bytes;
        const msg_len = msg_buf.length;
        const offset = out_buf.length;

        if (log == Logging.redacted) target_username = "[ redacted ]";
        if (log_msg && log != Logging.disabled) writeln(
            "Sending -> ", blue, msg.name, norm, " (code ", msg.code,
            ") -> to user ", blue, target_username, norm
        );

        if (msg_len > uint.max) {
            writeln(
                "Message ", red, msg.name, norm, " (code ", msg.code,
                ") of ", msg_len, " bytes to user ", blue, target_username,
                norm, " is too large, not sending"
            );
            return;
        }

        out_buf.length += (uint.sizeof + msg_len);
        out_buf[offset .. offset + uint.sizeof] = (cast(uint) msg_len)
            .nativeToLittleEndian;
        out_buf[offset + uint.sizeof .. $] = msg_buf;

        selector.register(sock.handle, SelectEvent.write);
    }

    bool recv_buffer(User target_user)
    {
        ubyte[max_msg_size] receive_buf;
        const receive_len = sock.receive(receive_buf);
        if (receive_len == Socket.ERROR || receive_len == 0)
            return false;

        in_buf ~= receive_buf[0 .. receive_len];
        while (true) {
            if (in_msg_size == -1) {
                if (in_buf.length < uint.sizeof)
                    break;
                in_msg_size = in_buf.read!(uint, Endian.littleEndian);
            }
            if (in_msg_size < 0 || in_msg_size > max_msg_size) {
                if (log_msg) writeln(
                    "Received unexpected message size ", in_msg_size,
                    " from user ", blue, target_user.username, norm,
                    ", disconnecting them"
                );
                return false;
            }
            if (in_buf.length < in_msg_size)
                break;

            if (!handle_message(target_user))
                break;
        }
        return true;
    }

    private void setup_socket()
    {
        enable_keep_alive();
        sock.setOption(SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1);
        sock.blocking = false;

        selector.register(sock.handle, SelectEvent.read);
    }

    private void enable_keep_alive()
    {
        int TCP_KEEPIDLE;
        int TCP_KEEPINTVL;
        int TCP_KEEPCNT;
        int TCP_KEEPALIVE_ABORT_THRESHOLD;
        int TCP_KEEPALIVE_THRESHOLD;

        version (linux) {
            TCP_KEEPIDLE                   = 0x4;
            TCP_KEEPINTVL                  = 0x5;
            TCP_KEEPCNT                    = 0x6;
        }
        version (OSX) {
            TCP_KEEPIDLE                   = 0x10;   // TCP_KEEPALIVE on macOS
            TCP_KEEPINTVL                  = 0x101;
            TCP_KEEPCNT                    = 0x102;
        }
        version (Windows) {
            TCP_KEEPIDLE                   = 0x03;
            TCP_KEEPCNT                    = 0x10;
            TCP_KEEPINTVL                  = 0x11;
        }
        version (FreeBSD) {
            TCP_KEEPIDLE                   = 0x100;
            TCP_KEEPINTVL                  = 0x200;
            TCP_KEEPCNT                    = 0x400;
        }
        version (NetBSD) {
            TCP_KEEPIDLE                   = 0x3;
            TCP_KEEPINTVL                  = 0x5;
            TCP_KEEPCNT                    = 0x6;
        }
        version (DragonFlyBSD) {
            TCP_KEEPIDLE                   = 0x100;
            TCP_KEEPINTVL                  = 0x200;
            TCP_KEEPCNT                    = 0x400;
        }
        version (Solaris) {
            TCP_KEEPALIVE_THRESHOLD        = 0x16;
            TCP_KEEPALIVE_ABORT_THRESHOLD  = 0x17;
        }

        const idle = 60;
        const interval = 5;
        const count = 10;

        if (TCP_KEEPIDLE)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPIDLE, idle
            );
        if (TCP_KEEPINTVL)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPINTVL,
                interval
            );
        if (TCP_KEEPCNT)
            sock.setOption(
                SocketOptionLevel.TCP, cast(SocketOption) TCP_KEEPCNT, count
            );
        if (TCP_KEEPALIVE_THRESHOLD)
            sock.setOption(
                SocketOptionLevel.TCP,
                cast(SocketOption) TCP_KEEPALIVE_THRESHOLD,
                idle * 1000              // milliseconds
            );
        if (TCP_KEEPALIVE_ABORT_THRESHOLD)
            sock.setOption(
                SocketOptionLevel.TCP,
                cast(SocketOption) TCP_KEEPALIVE_ABORT_THRESHOLD,
                count * interval * 1000  // milliseconds
            );

        sock.setOption(SocketOptionLevel.SOCKET, SocketOption.KEEPALIVE, true);
    }

    private void close()
    {
        if (sock is null)
            return;

        selector.unregister(sock.handle, SelectEvent.read | SelectEvent.write);

        sock.shutdown(SocketShutdown.BOTH);
        sock.close();
        sock = null;
    }

    private bool handle_message(User target_user)
    {
        auto msg_buf = in_buf[0 .. in_msg_size];
        const code = msg_buf.peek!(uint, Endian.littleEndian);
        const success = msg_handler.handle_message(target_user, code, msg_buf);

        if (success) {
            in_buf = in_buf[in_msg_size .. $];
            in_msg_size = -1;
        }
        return success;
    }
}
