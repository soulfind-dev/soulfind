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

private import std.stdio : readf, readln, write, writeln;
private import std.conv : to;
private import std.format : format;
private import std.algorithm : sort;
private import std.string : chomp, strip;

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
	auto m = new Menu ("Soulfind " ~ VERSION ~ " configuration");
	
	m.add ("0", "Admins",            &admins);
	m.add ("1", "Listen port",       &listen_port);
	m.add ("2", "Max users allowed", &max_users);
	m.add ("3", "MOTD",              &motd);
	m.add ("4", "Banned users",      &banned_users);
	m.add ("i", "Server info.",      &info);
	m.add ("q", "Exit",              &exit);
	
	m.show ();
	}

void exit ()
	{
	writeln ("\nA la prochaine...");
	exit(0);
	}

void admins ()
	{
	auto m = new Menu ("Admins");
	
	m.add ("1", "Add an admin",    &add_admin);
	m.add ("2", "Remove an admin", &del_admin);
	m.add ("3", "List admins",     &list_admins);
	m.add ("q", "Return",          &main_menu);

	m.show ();
	}

void add_admin ()
	{
	write ("Admin to add : ");
	auto admin = strip (to!string (readln ()));
	sdb.add_admin (admin);
	admins ();
	}

void del_admin ()
	{
	write ("Admin to remove : ");
	auto admin = strip (to!string (readln ()));
	sdb.del_admin (admin);
	admins ();
	}

void list_admins ()
	{
	auto names = sdb.get_admins ();

	if (names.length == 0)
		{
		writeln ("No admin on this server.");
		}
	else
		{
		writeln ("\nAdmins :");
		foreach (admin ; names)
			{
			writeln (format ("- %s", admin));
			}
		}
	
	admins ();
	}
	

void listen_port ()
	{
	auto m = new Menu (format ("Listen port : %d", sdb.conf_get_int ("port")));

	m.add ("1", "Change listen port", &set_listen_port);
	m.add ("q", "Return",             &main_menu);

	m.show ();
	}

void set_listen_port ()
	{
	write ("New listen port : ");
	auto port = strip (to!string (readln ()));
	sdb.conf_set_field ("port", port);
	listen_port ();
	}

void max_users ()
	{
	auto m = new Menu (format ("Max users allowed : %d", sdb.conf_get_int ("max_users")));

	m.add ("1", "Change max users", &set_max_users);
	m.add ("q", "Return",           &main_menu);

	m.show ();
	}

void set_max_users ()
	{
	write ("Max users : ");
	auto max_num_users = strip (to!string (readln ()));
	sdb.conf_set_field ("max_users", max_num_users);
	max_users ();
	}

void motd ()
	{
	auto m = new Menu (format ("Current message of the day :\n--\n%s\n--\n", sdb.conf_get_str ("motd")));

	m.add ("1", "Change MOTD", &set_motd);
	m.add ("q", "Return",      &main_menu);

	m.show ();
	}

void set_motd ()
	{
	writeln ("You can use the following variables :\n"
	        ~ "%version%     : server version (", VERSION, ")\n"
	        ~ "%nbusers%     : number of users already connected\n"
	        ~ "%username%    : name of the connecting user\n"
	        ~ "%userversion% : version of the user's client software\n"
	        ~ "New MOTD (end with a dot on a single line) :");

	string MOTD;

	do
		{
		string line;
		try
			{
			line = chomp (readln ());
			}
		catch (Exception e)
			{ // hopefully an EOF
			break;
			}

		if (strip (line) == ".")
			{
			break;
			}

		if (MOTD.length > 0)
			{
			MOTD ~= "\n";
			}

		MOTD ~= line;
		}
	while (true);

	sdb.conf_set_field ("motd", MOTD);
	motd ();
	}

void info ()
	{
	auto m = new Menu ("Misc. information :");

	m.info  = format ("Soulsetup for Soulfind %s, compiled on %s\n", VERSION, __DATE__);
	m.info ~= format ("%d registered users", sdb.nb_users ());

	m.add ("q", "Return", &main_menu);

	m.show ();
	}

void banned_users ()
	{
	auto m = new Menu ("Banned users");
	
	m.add ("1", "Ban an user",       &ban_user);
	m.add ("2", "Unban an user",     &unban_user);
	m.add ("3", "List banned users", &list_banned);
	m.add ("q", "Return",            &main_menu);

	m.show ();
	}

void ban_user ()
	{
	write ("User to ban : ");
	auto user = strip (to!string (readln ()));
	sdb.user_update_field (user, "banned", 1);
	banned_users ();
	}

void unban_user ()
	{
	write ("User to unban : ");
	auto user = strip (to!string (readln ()));
	sdb.user_update_field (user, "banned", 0);
	banned_users ();
	}

void list_banned ()
	{
	auto users = sdb.get_banned_usernames ();

	if (users.length == 0)
		{
		writeln ("No user is banned.");
		}
	else
		{
		writeln ("\nBanned users :");
		foreach (user ; users)
			{
			writeln (format ("- %s", user));
			}
		}
	
	banned_users ();
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
		writeln (format( "\n%s\n", title));

		if (info.length > 0) writeln (format ("%s\n", info));
		
		foreach (index ; sort(entries.keys))
			{
			writeln (format ("%s. %s", index, entries[index]));
			}

		write ("\nYour choice : ");

		auto answer = strip (to!string (readln ()));

		if (answer in actions)
			{
			actions[answer] ();
			}
		else
			{
			writeln ("Next time, try a number which has an action assigned to it...");
			show ();
			}
		}
	}
