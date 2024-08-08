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


module setup;

import defines;

private import db;

private import std.stdio : writeln;
private import undead.cstream;
private import std.conv : to;
private import std.format : format;
private import std.algorithm : sort;

private import core.sys.posix.stdlib : exit;

Sdb sdb;

void main (string[] args)
	{
	string db_file;
	
	if (args.length > 1)
		{
		if (args[1] == "--help" || args[1] == "-h")
			{
			writeln ("Usage: ", args[0], " [database_file]");
			writeln ("\tdatabase_file: path to Soulfind's database (default: ", default_db_file, ")");
			exit(0);
			}
		else
			{
			db_file = args[1];
			}
		}
	else
		{
		db_file = default_db_file;
		}

	sdb = new Sdb (db_file);

	main_menu ();
	}

void main_menu ()
	{
	Menu m = new Menu ("Soulfind " ~ VERSION ~ " configuration");
	
	m.add ("0", "Admins",            &admins);
	m.add ("1", "Listen port",       &listen_port);
	m.add ("2", "Max users allowed", &max_users);
	m.add ("3", "Max message size",  &max_size);
	m.add ("4", "Max offline PMs",   &max_pms);
	m.add ("5", "MOTD",              &motd);
	m.add ("6", "Banned users",      &banned_users);
	m.add ("7", "Server username",   &server_username);
	m.add ("8", "Case sensitivity",  &case_sensitivity);
	m.add ("i", "Server info.",      &info);
	m.add ("q", "Exit",              &exit);
	
	m.show ();
	}

void exit ()
	{
	dout.writeLine ("\nA la prochaine...");
	exit(0);
	}

void admins ()
	{
	Menu m = new Menu ("Admins");
	
	m.add ("1", "Add an admin",    &add_admin);
	m.add ("2", "Remove an admin", &del_admin);
	m.add ("3", "List admins",     &list_admins);
	m.add ("q", "Return",          &main_menu);

	m.show ();
	}

void add_admin ()
	{
	dout.writef ("Admin to add : ");
	sdb.add_admin (to!string(din.readLine ()));
	admins ();
	}

void del_admin ()
	{
	dout.writef ("Admin to remove : ");
	sdb.del_admin (to!string(din.readLine ()));
	admins ();
	}

void list_admins ()
	{
	string[] names = sdb.get_admins ();

	if (names.length == 0)
		{
		dout.writeLine ("No admin on this server.");
		}
	else
		{
		dout.writeLine ("\nAdmins :");
		foreach (string admin ; names)
			{
			dout.writeLine (format ("- %s", admin));
			}
		}
	
	admins ();
	}
	

void listen_port ()
	{
	Menu m = new Menu (format ("Listen port : %d", sdb.conf_get_int ("port")));

	m.add ("1", "Change listen port", &set_listen_port);
	m.add ("q", "Return",             &main_menu);

	m.show ();
	}

void set_listen_port ()
	{
	dout.writef ("New listen port : ");
	sdb.conf_set_field ("port", to!string(din.readLine()));
	listen_port ();
	}

void max_users ()
	{
	Menu m = new Menu (format ("Max users allowed : %d", sdb.conf_get_int ("max_users")));

	m.add ("1", "Change max users", &set_max_users);
	m.add ("q", "Return",           &main_menu);

	m.show ();
	}

void set_max_users ()
	{
	dout.writef ("Max users : ");
	sdb.conf_set_field ("max_users", to!string(din.readLine()));
	max_users ();
	}

void max_size ()
	{
	Menu m = new Menu (format ("Max client message size : %d", sdb.conf_get_int ("max_message_size")));

	m.add ("1", "Change max size", &set_max_size);
	m.add ("q", "Return",          &main_menu);

	m.show ();
	}

void set_max_size ()
	{
	dout.writef ("Max size : ");
	sdb.conf_set_field ("max_message_size", to!string(din.readLine()));
	max_size ();
	}

void max_pms ()
	{
	Menu m = new Menu (format ("Max number of offline PMs : %d", sdb.conf_get_int ("max_offline_pms")));

	m.add ("1", "Change number", &set_max_pms);
	m.add ("q", "Return",        &main_menu);

	m.show ();
	}

void set_max_pms ()
	{
	dout.writef ("Max PMs : ");
	sdb.conf_set_field ("max_offline_pms", to!string(din.readLine()));
	max_pms ();
	}

void motd ()
	{
	Menu m = new Menu (format ("Current message of the day :\n--\n%s\n--\n", sdb.conf_get_str ("motd")));

	m.add ("1", "Change MOTD", &set_motd);
	m.add ("q", "Return",      &main_menu);

	m.show ();
	}

void set_motd ()
	{
	writeln ("You can use the following variables :\n"
	        ~ "%%version%%     : server version (", VERSION, ")\n"
	        ~ "%%nbusers%%     : number of users already connected\n"
	        ~ "%%username%%    : name of the connecting user\n"
	        ~ "%%userversion%% : version of the user's client software\n"
	        ~ "New MOTD (end with a dot on a single line) :");

	string MOTD;
	char c, old;

	do
		{
		old = c;
		try
			{
			din.read (c);
			}
		catch (Exception e)
			{ // hopefully an EOF
			break;
			}
		if (c == '.' && old == '\n')
			{
			din.read (c); // there should be a \n left
			break;
			}
		else if (old == '\n')
			{
			MOTD ~= old;
			}
		
		if (c != '\n')
			{
			MOTD ~= old;
			}
		}
	while (true);

	sdb.conf_set_field ("motd", MOTD);

	motd ();
	}

void info ()
	{
	Menu m = new Menu ("Misc. information :");

	m.info  = format ("Soulsetup for Soulfind %s, compiled on %s\n", VERSION, __DATE__);
	m.info ~= format ("%d registered users", sdb.nb_users ());

	m.add ("q", "Return", &main_menu);

	m.show ();
	}

void banned_users ()
	{
	Menu m = new Menu ("Banned users");
	
	m.add ("1", "Ban an user",       &ban_user);
	m.add ("2", "Unban an user",     &unban_user);
	m.add ("3", "List banned users", &list_banned);
	m.add ("q", "Return",            &main_menu);

	m.show ();
	}

void ban_user ()
	{
	dout.writef ("User to ban : ");
	sdb.user_update_field (to!string(din.readLine()), "banned", 1);
	banned_users ();
	}

void unban_user ()
	{
	dout.writef ("User to unban : ");
	sdb.user_update_field (to!string(din.readLine()), "banned", 0);
	banned_users ();
	}

void list_banned ()
	{
	string[] users = sdb.get_banned_usernames ();

	if (users.length == 0)
		{
		dout.writeLine ("No user is banned.");
		}
	else
		{
		dout.writeLine ("\nBanned users :");
		foreach (string user ; users)
			{
			dout.writeLine (format ("- %s", user));
			}
		}
	
	banned_users ();
	}

void server_username ()
	{
	Menu m = new Menu ("Current username : " ~ sdb.conf_get_str ("server_user"));

	m.add ("1", "Change name", &set_server_username);
	m.add ("q", "Return",      &main_menu);

	m.show ();
	}

void set_server_username ()
	{
	dout.writef ("New name : ");
	sdb.conf_set_field ("server_user", to!string(din.readLine()));
	server_username ();
	}

void case_sensitivity ()
	{
	Menu m = new Menu ("Usernames are now case " ~ (sdb.conf_get_int ("case_insensitive") ? "insensitive" : "sensitive"));

	m.add ("1", "Toggle", &set_case_sensitivity);
	m.add ("q", "Return", &main_menu);

	m.show ();
	}

void set_case_sensitivity ()
	{
	sdb.conf_set_field ("case_insensitive", !sdb.conf_get_int ("case_insensitive"));
	case_sensitivity ();
	}

class Menu
	{
	string title;
	string info;
	string[string]           entries;
	void function ()[string] actions;
	
	this (string title)
		{
		this.title = title;
		}
	
	void add (string index, string entry, void function () action)
		{
		entries[index] = entry;
		actions[index] = action;
		}
	
	void show ()
		{
		dout.writeLine (format( "\n%s\n", title));

		if (info.length > 0) dout.writeLine (format ("%s\n", info));
		
		foreach (string index ; sort(entries.keys))
			{
			dout.writeLine (format ("%s. %s", index, entries[index]));
			}

		dout.write ("\nYour choice : ");

		string answer = to!string(din.readLine());

		if (answer in actions)
			{
			actions[answer] ();
			}
		else
			{
			dout.writeLine ("Next time, try a number which has an action assigned to it...");
			show ();
			}
		}
	}
