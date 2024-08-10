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

import defines;

private import client;
private import messages, message_codes;
private import db;
private import room;
private import pm;

private import std.stdio : write, writeln;
private import std.socket : Socket, TcpSocket, SocketOption, SocketOptionLevel, SocketSet, InternetAddress;
private import undead.socketstream : SocketStream;
private import std.conv : to;
private import std.array : split, join, replace;
private import core.stdc.stdlib : exit;
private import core.stdc.time : time;
private import std.utf : validate, UTFException;
private import std.format : format;
private import std.algorithm : canFind;
private import std.datetime : Duration, dur;
private import std.digest.md : md5Of;
private import std.string : strip;

private import core.sys.posix.unistd : fork, getpid;


void help (string[] args)
	{
	writeln ("Usage: ", args[0], " [database_file] [-d|--daemon]");
	writeln ("\tdatabase_file: path to the sqlite3 database (default: ", default_db_file, ")");
	writeln ("\t-d, --daemon : fork in the background");
	exit (0);
	}

void main (string[] args)
	{
	string db;
	
	bool daemon = false;

	if (args.length > 3) help (args);

	foreach (string arg ; args[1 .. $])
		{
		switch (arg)
			{
			case "-h":
			case "--help":
				help (args);
				break;
			case "-d":
			case "--daemon":
				daemon = true;
				break;
			default:
				db = arg;
				break;
			}
		}
	
	if (db.length == 0) db = default_db_file;
	if (daemon && fork ()) exit (0);
	
	Server s = new Server (db);
	s.listen ();

	if (!daemon) writeln ("Exiting.");
	}

class Server
	{
	ushort port;
	uint max_users;
	string motd;

	ulong started_at;	// for server uptime

	uint timeoutval = 240*1000000; // 2 minutes (µseconds)
	Duration timeout = dur!"minutes"(2);
	Sdb db; // users database

	Socket serverSocket;
	User[Socket] user_sockets;

	this (string db_file)
		{
		this.started_at = time(null);
		db = new Sdb (db_file);
	
		config ();
		}
	
	void listen ()
		{
		Socket socket = new TcpSocket ();
		try
			{
			socket.setOption (SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
			}
		catch (Exception e)
			{
			writeln ("Unable to set socket option REUSEADDR.");
			}
		try
			{
			socket.bind (new InternetAddress (port));
			socket.listen (10);
			}
		catch (Exception e)
			{
			write("Unable to bind socket to port ", port);
			if (port < 1024)
				writeln(", could it be that you're trying to use a port less than 1024 while running as a user ?");
			else
				writeln();
			exit (1789);
			}
		writeln("Process ", getpid(), " listening on port ", port);

		SocketSet sockset = new SocketSet (max_users + 1);
		
		
		while (true)
			{
			sockset.reset ();
			sockset.add (socket);
			foreach (Socket s ; user_sockets.keys) sockset.add (s);
			uint nb = Socket.select (sockset, null, null, timeout);
			if (nb == 0)
				{
				send_pings ();
				}
			if (sockset.isSet (socket))
				{
				nb--;
				debug (user) writeln ("Waiting for a connection...");
				Socket sock = socket.accept ();
				debug (user)
					{
					try {writeln ("Connection accepted from ", sock.remoteAddress().toString());}
					catch (Exception e) {writeln ("?");}
					}
				User user = new User (this, sock, (cast (InternetAddress) sock.remoteAddress()).addr());
				user_sockets[sock] = user;
				sockset.remove (socket);
				}
			foreach (Socket s ; user_sockets.keys)
				{
				if (nb == 0) break;
				if (s !is null && sockset.isSet (s))
					{
					nb--;
					if (!user_sockets[s].recv_message ())
						{
						user_sockets[s].exit ();
						sockset.remove (s);
						this.del_user (user_sockets[s]);
						user_sockets.remove (s);
						s.close ();
						}
					}
				}
			}
		}

	// Filesearches
	void do_FileSearch (uint token, string string, string username)
		{					// user who sends the search
		Message m = new SFileSearch (username, token, string);
		this.send_to_all (m);
		}

	void do_UserSearch (uint token, string string, string username, string to)
		{					// user who sends the search
							// to this user
		Message m = new SFileSearch (username, token, string);
		User u = get_user (to);

		if (u is null)
			{
			return;
			}
		else
			{
			u.send_message (m);
			}
		}
	
	void do_RoomSearch (uint token, string string, string username, string room)
		{
		Message m = new SFileSearch (username, token, string);

		Room r = Room.get_room (room);

		if (r is null)
			{
			return;
			}
		else
			{
			r.send_to_all (m);
			}
		}

	// Users
	private User[string] user_list;
	private string[string] passwords;
	ulong nb_users ()
		{
		return user_list.length;
		}
	
	string[] user_names ()
		{
		return user_list.keys;
		}
	
	User[] users ()
		{
		return user_list.values;
		}
	
	bool find_user (User user) {return find_user (user.username);}
	bool find_user (string username)
		{
		return (username in user_list) ? true : false;
		}
	
	User get_user (string username)
		{
		if (find_user (username))
			{
			return user_list[username];
			}
		else
			{
			return null;
			}
		}

	void add_user (User user)
		{
		user_list[user.username] = user;
		}

	void del_user (User user)
		{
		if (user.socket in user_sockets) user_sockets.remove (user.socket);
		if (find_user (user)) user_list.remove (user.username);
		}

	void send_pings ()
		{
		foreach (User u ; users ())
			{
			if ((time(null) - u.last_message_date) >= timeout.total!"seconds")
				{
				u.send_message (new SServerPing ());
				}
			}
		}
	
	void send_to_all (Message m)
		{
		debug (msg) write("Sending message (", blue,  message_name[m.code], black, " - code ", blue, m.code, black, ") to all users");
		foreach (User u ; users ())
			{
			debug (msg) write (".");
			u.send_message (m);
			}
		debug (msg) writeln ();
		}
	
	// recommendations
	uint[string] global_recommendations ()
		{
		uint[string] list;
		
		foreach (User u ; this.users ())
			{
			foreach (string thing ; u.things_he_likes)
				{
				list[thing]++;
				}
			}

		return list;
		}

	// admin
	string[string]	admins;
	
	void del_admin (string name)
		{
		if (name in admins) admins.remove (name);
		this.db.del_admin (name);
		}

	void add_admin (string name)
		{
		admins[name] = name;
		this.db.add_admin (name);
		
		if (find_user (name)) get_user (name).admin = true;
		}

	void admin_message (User admin, string message)
		{
		string[] command = message.split(" ");
		if (command.length > 0) switch (command[0])
			{
			case "help":
				//this.adminpm (admin, "nbusers, users, info <user>, killall, kill <user>, [un]ban <user>, (add|del)admin <user>, admins, rooms, addprivileges <days> <user>, message <message>, uptime, reload");
				this.adminpm (admin, "Available commands :\n\n"
						   ~ "nbusers\n\tNumber of users connected\n\n"
				           ~ "users\n\tInfo about each connected user\n\n"
						   ~ "info <user>\n\tInfo about user <user>\n\n"
						   ~ "killall\n\tDisconnect all users\n\n"
						   ~ "kill <user>\n\tDisconnect <user>\n\n"
						   ~ "[un]ban <user>\n\tUnban or ban and disconnect user <user>\n\n"
						   ~ "(add|del)admin <user>\n\tMake <user> an admin\n\n"
						   ~ "admins\n\tList admins\n\n"
						   ~ "rooms\n\tList rooms and number of occupiants\n\n"
						   ~ "addprivileges <days> <user>\n\tAdd <days> days of privileges to user <user>\n\n"
						   ~ "message <message>\n\tSend global message <message>\n\n"
						   ~ "uptime\n\tShow server uptime\n\n"
						   ~ "reload\n\tReload settings (Admins, MOTD, etc)");
				break;
			case "addprivileges":
				uint days;
				if (command.length < 3)
					{
					this.adminpm (admin, "Syntax is : addprivileges <days> <user>");
					break;
					}
				try
					{
					days = to!uint(command[1]);
					}
				catch (Exception e)
					{
					this.adminpm (admin, "Badly formatted number.");
					break;
					}
				string user = join (command[2 .. $], " ");
				if (this.find_user (user))
					{
					this.get_user (user).add_privileges (days*3600*24);
					}
				else
					{
					this.adminpm (admin, format ("User %s does not exist.", user));
					}
				break;
			case "nbusers":
				this.adminpm (admin, format ("%d connected users.", this.nb_users ()));
				break;
			case "users":
				this.adminpm (admin, this.show_users());
				break;
			case "info":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : info <user>");
					break;
					}
				this.adminpm (admin, this.show_user (join (command[1 .. $], " ")));
				break;
			case "killall":
				debug (user) writeln ("Admin request to kill ALL users...");
				this.kill_all_users ();
				break;
			case "kill":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : kill <user>");
					break;
					}
				this.kill_user (join (command[1 .. $], " "));
				this.adminpm (admin, format ("User %s kicked from the server", join (command[1 .. $], " ")));
				break;
			case "ban":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : ban <user>");
					break;
					}
				this.ban_user (join (command[1 .. $], " "));
				this.adminpm (admin, format ("User %s banned from the server", join (command[1 .. $], " ")));
				break;
			case "unban":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : unban <user>");
					break;
					}
				this.unban_user (join (command[1 .. $], " "));
				this.adminpm (admin, format ("User %s not banned anymore", join (command[1 .. $], " ")));
				break;
			case "addadmin":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : addadmin <user>");
					break;
					}
				this.add_admin (join (command[1 .. $], " "));
				break;
			case "deladmin":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : deladmin <user>");
					break;
					}
				this.del_admin (join (command[1 .. $], " "));
				break;
			case "admins":
				string list;
				foreach (string s ; this.admins)
					{
					list ~= s ~ " ";
					}
				this.adminpm (admin, list);
				break;
			case "rooms":
				string list;
				foreach (Room r ; Room.rooms ())
					{
					list ~= format ("%s:%d ", r.name, r.nb_users ());
					}
				this.adminpm (admin, list);
				break;
			case "message":
				if (command.length < 2)
					{
					this.adminpm (admin, "Syntax is : message <message>");
					break;
					}
				this.global_message (join (command[1 .. $], " "));
				break;
			case "uptime":
				this.adminpm (admin, print_length (uptime ()));
				break;
			case "reload":
				this.config (true);
				this.adminpm (admin, "Configuration and admins list reloaded");
				break;
			default:
				this.adminpm (admin, "Don't expect me to understand what you want if you don't use a correct command...");
				break;
			}
		}
	
	void adminpm (User admin, string message)
		{
		PM pm = new PM (message, server_user, admin.username);
		bool new_message = true;
		admin.send_pm (pm, new_message);
		}
	
	void global_message (string message)
		{
		foreach (User user ; user_list)
			{
			user.send_message (new SAdminMessage (message));
			}
		}
	
	string show_users ()
		{
		string s;
		foreach (string username ; this.user_names ())
			{
			s ~= this.show_user (username) ~ "\n";
			}
		return s;
		}
	
	string show_user (string username)
		{
		if (this.find_user (username))
			{
			User user = this.get_user (username);
			return format("%s: connected at %s"
						~ "\n\tclient version: %s"
						~ "\n\taddress: %s"
						~ "\n\tadmin: %s"
						~ "\n\tfiles: %s"
						~ "\n\tdirs: %s"
						~ "\n\tstatus: %s"
						~ "\n\tprivileges: %s"
						~ "\n\tjoined rooms: %s",
					        user.username,
						    user.connected_at,
						    user.cversion,
						    (cast (SocketStream) user.stream).socket.remoteAddress().toString(),
						    user.admin,
						    user.shared_files,
						    user.shared_folders,
						    user.status,
						    user.print_privileges (),
						    user.list_joined_rooms ());
			}
		else return "";
		}

	void kill_all_users () 
		{
		foreach (User user ; this.user_list)
			{
			user.exit ();
			}
		}
	
	void kill_user (string user)
		{
		if (this.find_user (user))
			{
			get_user (user).exit ();
			}
		}

	void ban_user (string user)
		{
		if (this.db.user_exists (user))
			{
			db.user_update_field (user, "banned", 1);
			get_user (user).exit ();
			}
		}

	void unban_user (string user)
		{
		if (this.db.user_exists (user))
			{
			db.user_update_field (user, "banned", 0);
			}
		}

	string get_motd (string name, uint vers)
		{
		string ret;
		ret = replace (this.motd, "%version%", VERSION);
		ret = replace (ret, "%nbusers%", to!string(this.nb_users ()));
		ret = replace (ret, "%username%", name);
		ret = replace (ret, "%userversion%", to!string(vers));
		return ret;
		}

	// config
	void config (bool reload = false)
		{
		if (!reload) this.port		= cast(ushort)db.conf_get_int ("port");
		if (!reload) this.max_users	= db.conf_get_int ("max_users");
		this.motd					= db.conf_get_str ("motd");

		foreach (string admin ; db.get_admins ())
			{
			this.admins[admin] = admin;
			}
		}
	
	ulong uptime ()	// returns uptime, in seconds
		{
		return time(null) - this.started_at;
		}
	
	string print_uptime ()
		{
		return print_length (uptime);
		}
	

	string encode_password (string pass)
		{
		ubyte[16] digest = md5Of(pass);
		string s;
		foreach (ubyte u ; digest)
			{
			s ~= format ("%02x", u);
			}
		return s;
		}
	
	bool check_string (string str)
		{
		try
			{
			validate (str);
			}
		catch (UTFException)
			{
			return false;
			}

		if (strip (str) != str)
			{
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

		foreach (dchar c ; forbidden)
			{
			if (canFind(str, c))
				{
				return false;
				}
			}

		return true;
		}
	
	bool check_login (string user, string pass, uint vers, out string error)
		{
		if (!db.user_exists (user))
			{
			if (!check_string (user) || user == server_user)
				{
				error = "INVALIDUSERNAME";
				return false;
				}

			debug (user) writeln ("Adding user ", user, "...");
			db.add_user (user, encode_password (pass));
			return true;
			}
		else
			{
			debug (user) writeln ("User ", user, " is registered, checking banned status and password...");
			if (db.is_banned (user))
				{
				error = "BANNED";
				return false;
				}
			else
				{
				string real_pass = db.get_pass (user);

				if (real_pass == encode_password (pass) || real_pass == pass)
					{
					return true;
					}
				else
					{
					error = "INVALIDPASS";
					return false;
					}
				}
			}
		}
	}


string print_length (ulong length)
	{
	ulong d = length/(60*60*24);
	ulong h = length/(60*60) - d*24;
	ulong m = length/(60) - d*60*24 - h*60;
	ulong s = length - d*60*60*24 - h*60*60 - m*60;
	
	string l;
	if (d > 0) l ~= format ("%d %s, ", d, d > 1 ? "days" : "day");
	if (d > 0 || h > 0) l ~= format ("%d %s, ", h, h > 1 ? "hours" : "hour");
	if (d > 0 || h > 0 || m > 0) l ~= format ("%d %s, ", m, m > 1 ? "minutes" : "minute");
	if (d > 0 || h > 0 || m > 0 || s > 0) l ~= format ("%d %s", s, s > 1 ? "seconds" : "second");
	return l;
	}
