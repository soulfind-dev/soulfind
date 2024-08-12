/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + SoulFind - Free SoulSeek server                                           +
 +                                                                           +
 + Copyright(C) 2005 SeeSchloss <seeschloss@seeschloss.org>                 +
 +                                                                           +
 + This  program  is free software ; you can  redistribute it  and/or modify +
 + it under  the  terms of  the GNU General Public License  as published  by +
 + the  Free  Software  Foundation ;  either  version  2 of  the License, or +
 +(at your option) any later version.                                       +
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
@safe:

import defines;

private import db;

private import std.algorithm : sort;
private import std.conv : to;
private import std.format : format;
private import std.stdio : readf, readln, write, writeln;
private import std.string : chomp, strip;

Sdb sdb;

void main(string[] args)
{
	string db_file = default_db_file;
	
	if (args.length > 1) {
		if (args[1] == "--help" || args[1] == "-h") {
			writeln("Usage: ", args[0], " [database_file]");
			writeln(
				"\tdatabase_file: path to Soulfind's database "
				~ "(default: ", default_db_file, ")"
			);
			return;
		}
		db_file = args[1];
	}

	sdb = new Sdb(db_file);
	main_menu();
	return;
}

@trusted
string input()
{
	return readln();
}

void main_menu()
{
	auto menu = new Menu("Soulfind " ~ VERSION ~ " configuration");
	
	menu.add("0", "Admins",            &admins);
	menu.add("1", "Listen port",       &listen_port);
	menu.add("2", "Max users allowed", &max_users);
	menu.add("3", "MOTD",              &motd);
	menu.add("4", "Banned users",      &banned_users);
	menu.add("i", "Server info.",      &info);
	menu.add("q", "Exit",              &exit);
	
	menu.show();
}

void exit()
{
	writeln("\nA la prochaine...");
}

void admins()
{
	auto menu = new Menu("Admins");
	
	menu.add("1", "Add an admin",    &add_admin);
	menu.add("2", "Remove an admin", &del_admin);
	menu.add("3", "List admins",     &list_admins);
	menu.add("q", "Return",          &main_menu);

	menu.show();
}

void add_admin()
{
	write("Admin to add : ");
	sdb.add_admin(input.strip);
	admins();
}

void del_admin()
{
	write("Admin to remove : ");
	sdb.del_admin(input.strip);
	admins();
}

void list_admins()
{
	auto names = sdb.get_admins();

	if (!names) {
		writeln("No admin on this server.");
		admins();
		return;
	}

	writeln("\nAdmins :");
	foreach (admin ; names) writeln(format("- %s", admin));

	admins();
}
	

void listen_port()
{
	auto menu = new Menu(
		format("Listen port : %d", sdb.conf_get_int("port"))
	);
	menu.add("1", "Change listen port", &set_listen_port);
	menu.add("q", "Return",             &main_menu);

	menu.show();
}

void set_listen_port()
{
	write("New listen port : ");
	sdb.conf_set_field("port", input.strip);
	listen_port();
}

void max_users()
{
	auto menu = new Menu(
		format("Max users allowed : %d",
			sdb.conf_get_int("max_users"))
	);
	menu.add("1", "Change max users", &set_max_users);
	menu.add("q", "Return",           &main_menu);

	menu.show();
}

void set_max_users()
{
	write("Max users : ");
	sdb.conf_set_field("max_users", input.strip);
	max_users();
}

void motd()
{
	auto menu = new Menu(
		format("Current message of the day :\n--\n%s\n--\n",
			sdb.conf_get_str("motd"))
	);
	menu.add("1", "Change MOTD", &set_motd);
	menu.add("q", "Return",      &main_menu);

	menu.show();
}

void set_motd()
{
	writeln(
		"You can use the following variables :\n"
		~ "%version%     : server version(", VERSION, ")\n"
		~ "%nbusers%     : number of users already connected\n"
		~ "%username%    : name of the connecting user\n"
		~ "%userversion% : version of the user's client software\n"
		~ "New MOTD(end with a dot on a single line) :"
	);

	string MOTD;

	do {
		auto line = input.chomp;
		if (line.strip == ".")
			break;
		if (MOTD.length > 0) MOTD ~= "\n";
		MOTD ~= line;
	}
	while(true);

	sdb.conf_set_field("motd", MOTD);
	motd();
}

void info()
{
	auto menu = new Menu("Misc. information :");

	menu.info  = format(
		"Soulsetup for Soulfind %s, compiled on %s\n",
		VERSION, __DATE__
	);
	menu.info ~= format("%d registered users", sdb.nb_users());
	menu.add("q", "Return", &main_menu);

	menu.show();
}

void banned_users()
{
	auto menu = new Menu("Banned users");
	
	menu.add("1", "Ban an user",       &ban_user);
	menu.add("2", "Unban an user",     &unban_user);
	menu.add("3", "List banned users", &list_banned);
	menu.add("q", "Return",            &main_menu);

	menu.show();
}

void ban_user()
{
	write("User to ban : ");
	sdb.user_update_field(input.strip, "banned", 1);
	banned_users();
}

void unban_user()
{
	write("User to unban : ");
	sdb.user_update_field(input.strip, "banned", 0);
	banned_users();
}

void list_banned()
{
	auto users = sdb.get_banned_usernames();

	if (!users) {
		writeln("No user is banned.");
		banned_users();
		return;
	}

	writeln("\nBanned users :");
	foreach (user ; users) writeln(format("- %s", user));

	banned_users();
}

class Menu
{
	string title;
	string info;
	string[string]           entries;
	void function()[string] actions;
	
	this(string title)
	{
		this.title = title;
	}
	
	void add(string index, string entry, void function() @safe action)
	{
		entries[index] = entry;
		actions[index] = action;
	}
	
	void show()
	{
		writeln(format( "\n%s\n", title));
		if (info.length > 0) writeln(format("%s\n", info));
		
		foreach (index ; sort(entries.keys))
			writeln(format("%s. %s", index, entries[index]));

		write("\nYour choice : ");
		auto choice = input.strip;

		if (choice !in actions)
		{
			writeln(
				"Next time, try a number which has an action "
				~ "assigned to it..."
			);
			show();
			return;
		}
		actions[choice]();
	}
}
