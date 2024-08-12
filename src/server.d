/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + SoulFind - Free SoulSeek server                                           +
 +                                                                           +
 + Copyright (C) 2005 SeeSchloss <seeschloss@seeschloss.org>                 +
 +                                                                           +
 + This  program  is free software ; you can  redistribute it  and/or modify +
 + it under  the  terms of  the GNU General Public License  as published  by +
 + the  Free  Software  Foundation ;  either  version  2 of  the License, or +
 + (at your option) any later version.                                       +
 +                                                                           +
 + This  program  is  distributed  in the  hope  that  it  will  be  useful, +
 + but   WITHOUT  ANY  WARRANTY ;  without  even  the  implied  warranty  of +
 + MERCHANTABILITY   or   FITNESS   FOR   A   PARTICULAR  PURPOSE.  See  the +
 + GNU General Public License for more details.                              +
 +                                                                           +
 + You  should  have  received  a  copy  of  the  GNU General Public License +
 + along   with  this  program ;  if  not,  write   to   the  Free  Software +
 + Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA +
 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/


module server;
@safe:

import defines;

private import client;
private import messages, message_codes;
private import db;
private import room;
private import pm;

private import std.stdio : write, writeln;
private import std.socket : Socket, TcpSocket, SocketOption, SocketOptionLevel,
							SocketSet, InternetAddress, SocketAcceptException,
							SocketShutdown;
private import std.conv : to;
private import std.array : split, join, replace;
private import core.stdc.time : time;
private import std.utf : validate, UTFException;
private import std.format : format;
private import std.algorithm : canFind;
private import std.datetime : Duration, dur;
private import std.digest.md : md5Of;
private import std.string : strip;
private import std.process : thisProcessID;

private import core.sys.posix.unistd : fork;


private void help(string[] args)
{
	writeln("Usage: ", args[0], " [database_file] [-d|--daemon]");
	writeln(
		"\tdatabase_file: path to the sqlite3 database(default: ",
		default_db_file, ")"
	);
	writeln("\t-d, --daemon : fork in the background");
}

private int main(string[] args)
{
	bool daemon;
	string db = default_db_file;

	if (args.length > 3) help(args);

	foreach (arg ; args[1 .. $]) {
		switch(arg) {
			case "-h":
			case "--help":
				help(args);
				return 0;
			case "-d":
			case "--daemon":
				daemon = true;
				break;
			default:
				db = arg;
				break;
		}
	}

	if (daemon && fork())
		return 0;

	Server s = new Server(db);
	return s.listen();
}

class Server
{
	Sdb						db; 						// users database

	private ushort			port;
	private uint			max_users;
	private string			motd;

	private ulong			started_at;					// for server uptime

	private Socket			sock;
	private User[Socket]	user_socks;
	private auto			keepalive_time = 60;
	private auto			keepalive_interval = 5;
	private Duration		select_timeout = dur!"minutes"(2);

	private this(string db_file)
	{
		started_at = time(null);
		db = new Sdb(db_file);

		config();
	}

	private int listen()
	{
		sock = new TcpSocket();
		sock.blocking = false;
		sock.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);

		try {
			sock.bind(new InternetAddress(port));
			sock.listen(10);
		}
		catch (Exception e) {
			write("Unable to bind socket to port ", port);
			if (port < 1024)
				writeln(
					", could it be that you're trying to use a port less than "
					~ "1024 while running as a user ?"
				);
			else
				writeln();
			return 1789;
		}

		writeln("Process ", thisProcessID, " listening on port ", port);

		auto read_socks = new SocketSet(max_users + 1);
		auto write_socks = new SocketSet(max_users + 1);

		while(true) {
			read_socks.reset();
			write_socks.reset();
			read_socks.add(sock);

			foreach (user_sock, user ; user_socks) {
				read_socks.add(user_sock);
				if (user.is_sending) write_socks.add(user_sock);
			}

			auto nb = Socket.select(
				read_socks, write_socks, null, select_timeout
			);

			if (read_socks.isSet(sock)) {
				while(true) {
					Socket new_sock;
					try {
						new_sock = sock.accept();
					}
					catch (SocketAcceptException) {
						break;
					}
					new_sock.setKeepAlive(keepalive_time, keepalive_interval);
					new_sock.setOption(
						SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1
					);
					new_sock.blocking = false;

					debug (user) {
						writeln(
							"Connection accepted from ", new_sock.remoteAddress
						);
					}

					auto user = new User(
						this, new_sock,
						(cast(InternetAddress) new_sock.remoteAddress).addr
					);
					user_socks[new_sock] = user;
				}
				nb--;
				read_socks.remove(sock);
			}

			foreach (user_sock, user ; user_socks) {
				if (nb == 0)
					break;

				auto recv_success = true;
				auto send_success = true;
				bool changed;

				if (read_socks.isSet(user_sock)) {
					recv_success = user.recv_buffer();
					changed = true;
				}
				if (write_socks.isSet(user_sock)) {
					send_success = user.send_buffer();
					changed = true;
				}

				if (changed) nb--;
				if (recv_success && send_success)
					continue;

				user.exit();
				read_socks.remove(user_sock);
				write_socks.remove(user_sock);
				del_user(user);
				user_sock.shutdown(SocketShutdown.BOTH);
				user_sock.close();
			}
		}

		writeln("Exiting.");
		return 0;
	}

	// Filesearches
	void do_FileSearch(uint token, string query, string username)
	{
		auto msg = new SFileSearch(username, token, query);
		send_to_all(msg);
	}

	void do_UserSearch(uint token, string query, string username, string to)
	{
		auto msg = new SFileSearch(username, token, query);
		auto user = get_user(to);
		if (!user)
			return;

		user.send_message(msg);
	}

	void do_RoomSearch(uint token, string query, string username,
						string room_name)
	{
		auto msg = new SFileSearch(username, token, query);
		auto room = Room.get_room(room_name);
		if (!room)
			return;

		room.send_to_all(msg);
	}

	// Users
	private User[string] user_list;

	void add_user(User user)
	{
		user_list[user.username] = user;
	}

	bool find_user(User user)
	{
		return(user.username in user_list) ? true : false;
	}

	User get_user(string username)
	{
		if (username in user_list)
			return user_list[username];

		return null;
	}

	User[] users()
	{
		return user_list.values;
	}

	private void del_user(User user)
	{
		if (user.sock in user_socks) user_socks.remove(user.sock);
		if (user.username in user_list) user_list.remove(user.username);
	}

	private ulong nb_users()
	{
		return user_list.length;
	}

	private void send_to_all(Message msg)
	{
		debug (msg) write(
			"Sending message(", blue,  message_name[msg.code], black,
			" - code ", blue, msg.code, black, ") to all users"
		);
		foreach (user ; users)
		{
			debug (msg) write(".");
			user.send_message(msg);
		}
		debug (msg) writeln();
	}

	// admin
	private string[string]	admins;

	void admin_message(User admin, string message)
	{
		auto command = message.split(" ");
		if (command.length > 0) switch(command[0])
		{
			case "help":
				admin_pm(
					admin,
					"Available commands :\n\n"
				  ~ "nbusers\n\tNumber of users connected\n\n"
				  ~ "users\n\tInfo about each connected user\n\n"
				  ~ "info <user>\n\tInfo about user <user>\n\n"
				  ~ "killall\n\tDisconnect all users\n\n"
				  ~ "kill <user>\n\tDisconnect <user>\n\n"
				  ~ "[un]ban <user>\n\tUnban or ban and disconnect"
				  ~ " user <user>\n\n"
				  ~ "(add|del)admin <user>\n\tMake <user> an"
				  ~ " admin\n\n"
				  ~ "admins\n\tList admins\n\n"
				  ~ "rooms\n\tList rooms and number of"
				  ~ " occupiants\n\n"
				  ~ "addprivileges <days> <user>\n\tAdd <days>"
				  ~ " days of privileges to user <user>\n\n"
				  ~ "message <message>\n\tSend global message"
				  ~ " <message>\n\n"
				  ~ "uptime\n\tShow server uptime\n\n"
				  ~ "reload\n\tReload settings(Admins, MOTD, etc)"
				);
				break;

			case "addprivileges":
				if (command.length < 3) {
					admin_pm(admin, "Syntax is : addprivileges <days> <user>");
					break;
				}

				uint days;
				try {
					days = command[1].to!uint;
				}
				catch (Exception e) {
					admin_pm(admin, "Badly formatted number.");
					break;
				}

				auto username = join(command[2 .. $], " ");
				auto user = get_user(username);
				if (!user) {
					admin_pm(
						admin, format("User %s does not exist.", username)
					);
					break;
				}

				user.add_privileges(days * 3600 * 24);
				break;

			case "nbusers":
				auto num_users = nb_users;
				admin_pm(admin, format("%d connected users.", num_users));
				break;

			case "users":
				auto users = show_users();
				admin_pm(admin, users);
				break;

			case "info":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : info <user>");
					break;
				}
				auto username = join(command[1 .. $], " ");
				auto user_info = show_user(username);
				admin_pm(admin, user_info);
				break;

			case "killall":
				debug (user) writeln("Admin request to kill ALL users...");
				kill_all_users();
				break;

			case "kill":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : kill <user>");
					break;
				}
				auto username = join(command[1 .. $], " ");
				kill_user(username);
				admin_pm(
					admin, format("User %s kicked from the server", username)
				);
				break;

			case "ban":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : ban <user>");
					break;
				}
				auto username = join(command[1 .. $], " ");
				ban_user(username);
				admin_pm(
					admin, format("User %s banned from the server", username)
				);
				break;

			case "unban":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : unban <user>");
					break;
				}
				auto username = join(command[1 .. $], " ");
				unban_user(username);
				admin_pm(
					admin, format("User %s not banned anymore", username)
				);
				break;

			case "addadmin":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : addadmin <user>");
					break;
				}
				auto admin_name = join(command[1 .. $], " ");
				add_admin(admin_name);
				break;

			case "deladmin":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : deladmin <user>");
					break;
				}
				auto admin_name = join(command[1 .. $], " ");
				del_admin(admin_name);
				break;

			case "admins":
				string list;
				foreach (admin_name ; admins) list ~= admin_name ~ " ";
				admin_pm(admin, list);
				break;

			case "rooms":
				string list;
				foreach (room ; Room.rooms)
					list ~= format("%s:%d ", room.name, room.nb_users);
				admin_pm(admin, list);
				break;

			case "message":
				if (command.length < 2) {
					admin_pm(admin, "Syntax is : message <message>");
					break;
				}
				auto msg = join(command[1 .. $], " ");
				global_message(msg);
				break;

			case "uptime":
				admin_pm(admin, print_length(uptime));
				break;

			case "reload":
				config(true);
				admin_pm(admin, "Configuration and admins list reloaded");
				break;

			default:
				admin_pm(
					admin,
					"Don't expect me to understand what you want if you don't "
				  ~ "use a correct command..."
				);
				break;
		}
	}

	bool is_admin(string name)
	{
			return name in admins ? true : false;
	}

	private void add_admin(string name)
	{
		admins[name] = name;
		db.add_admin(name);
	}

	private void del_admin(string name)
	{
		if (name in admins) admins.remove(name);
		db.del_admin(name);
	}

	private void admin_pm(User admin, string message)
	{
		PM pm = new PM(message, server_user, admin.username);
		bool new_message = true;
		admin.send_pm(pm, new_message);
	}

	private void global_message(string message)
	{
		foreach (User user ; user_list) {
			user.send_message(new SAdminMessage(message));
		}
	}

	private string show_users()
	{
		string s;
		foreach (username ; user_list.keys) s ~= show_user(username) ~ "\n";
		return s;
	}

	private string show_user(string username)
	{
		auto user = get_user(username);
		if (!user)
			return "";

		return format("%s: connected at %s"
					~ "\n\tclient version: %s"
					~ "\n\taddress: %s"
					~ "\n\tadmin: %s"
					~ "\n\tfiles: %s"
					~ "\n\tdirs: %s"
					~ "\n\tstatus: %s"
					~ "\n\tprivileges: %s"
					~ "\n\tjoined rooms: %s",
						username,
						user.connected_at,
						user.cversion,
						user.sock.remoteAddress,
						is_admin(username),
						user.shared_files,
						user.shared_folders,
						user.status,
						user.print_privileges,
						user.list_joined_rooms);
	}

	private void kill_all_users()
	{
		foreach (user ; user_list) user.exit();
	}

	private void kill_user(string username)
	{
		auto user = get_user(username);
		if (user) user.exit();
	}

	private void ban_user(string username)
	{
		if (!db.user_exists(username))
			return;

		db.user_update_field(username, "banned", 1);
		get_user(username).exit();
	}

	private void unban_user(string username)
	{
		if (db.user_exists(username))
			db.user_update_field(username, "banned", 0);
	}

	string get_motd(string name, uint vers)
	{
		string ret;
		ret = replace(motd, "%version%", VERSION);
		ret = replace(ret, "%nbusers%", nb_users.to!string);
		ret = replace(ret, "%username%", name);
		ret = replace(ret, "%userversion%", vers.to!string);
		return ret;
	}

	private void config(bool reload = false)
	{
		motd = db.conf_get_str("motd");
		if (!reload) {
			port = cast(ushort)db.conf_get_int("port");
			max_users = db.conf_get_int("max_users");
		}

		foreach (admin ; db.get_admins()) {
			admins[admin] = admin;
		}
	}

	private ulong uptime()
	{
		return time(null) - started_at;
	}

	private string print_uptime()
	{
		return print_length(uptime);
	}

	private string encode_password(string pass)
	{
		ubyte[16] digest = md5Of(pass);
		string s;
		foreach (u ; digest) s ~= format("%02x", u);
		return s;
	}

	bool check_string(string str)
	{
		try {
			validate(str);
		}
		catch (UTFException) {
			return false;
		}

		if (strip(str) != str) {
			// leading/trailing whitespace
			return false;
		}

		dstring forbidden = ['\u0000', '\u0001', '\u0002', '\u0003', '\u0004', '\u0005'
			 , '\u0006', '\u0007', '\u0008', '\u0009', '\u000A', '\u000B', '\u000D', '\u000E'
			 , '\u000F', '\u0010', '\u0011', '\u0012', '\u0013', '\u0014', '\u0015', '\u0016'
			 , '\u0017', '\u0018', '\u0019', '\u001A', '\u001B', '\u001C', '\u001D', '\u001E'
			 , '\u001F', '\u007F', '\u0080', '\u0081', '\u0082', '\u0083', '\u0084', '\u0085'
			 , '\u0086', '\u0087', '\u0088', '\u0089', '\u008A', '\u008B', '\u008C', '\u008D'
			 , '\u008E', '\u008F', '\u0090', '\u0091', '\u0092', '\u0093', '\u0094', '\u0095'
			 , '\u0096', '\u0097', '\u0098', '\u0099', '\u009A', '\u009B', '\u009C', '\u009D'
			 , '\u009E', '\u009F', '\u00A0', '\u00AD'
			  // some control chars

			 , '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007'
			 , '\u2008', '\u2009', '\u200A', '\u200B', '\u200C', '\u200D', '\u200E', '\u200F'];
			  // separators, joiners, etc

		foreach (dchar c ; forbidden) {
			if (canFind(str, c)) {
				return false;
			}
		}
		return true;
	}

	bool check_login(string username, string pass, uint vers, out string error)
	{
		if (!db.user_exists(username)) {
			if (!check_string(username) || username == server_user) {
				error = "INVALIDUSERNAME";
				return false;
			}

			debug (user) writeln("Adding user ", username, "...");
			db.add_user(username, encode_password(pass));
			return true;
		}
		else {
			debug (user) writeln(
				"User ", username,
				" is registered, checking banned status and password..."
			);
			if (db.is_banned(username)) {
				error = "BANNED";
				return false;
			}
			else {
				string real_pass = db.get_pass(username);

				if (real_pass == encode_password(pass) || real_pass == pass) {
					return true;
				}
				else {
					error = "INVALIDPASS";
					return false;
				}
			}
		}
	}
}


string print_length(ulong length)
{
	auto d = length /(60 * 60 * 24);
	auto h = length /(60 * 60) - d * 24;
	auto m = length /(60) - d * 60 * 24 - h * 60;
	auto s = length - d * 60 * 60 * 24 - h * 60 * 60 - m * 60;

	string l;
	if (d > 0) l ~= format("%d %s, ", d, d > 1 ? "days" : "day");
	if (d > 0 || h > 0) l ~= format("%d %s, ", h, h > 1 ? "hours" : "hour");
	if (d > 0 || h > 0 || m > 0) l ~= format("%d %s, ", m, m > 1 ? "minutes" : "minute");
	if (d > 0 || h > 0 || m > 0 || s > 0) l ~= format("%d %s", s, s > 1 ? "seconds" : "second");
	return l;
}
