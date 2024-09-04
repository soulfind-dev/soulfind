// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module setup;
@safe:

import defines;

import db;

import std.algorithm : sort;
import std.conv : ConvException, to;
import std.format : format;
import std.stdio : readf, readln, write, writefln;
import std.string : chomp, strip;

Sdb sdb;

void main(string[] args)
{
	string db_file = default_db_file;

	if (args.length > 1) {
		if (args[1] == "--help" || args[1] == "-h") {
			writefln("Usage: %s [database_file]", args[0]);
			writefln(
				"\tdatabase_file: path to Soulfind's database (default: %s)",
				default_db_file
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
	auto menu = new Menu("Soulfind %s configuration".format(VERSION));

	menu.add("0", "Admins",            &admins);
	menu.add("1", "Listen port",       &listen_port);
	menu.add("2", "Max users allowed", &max_users);
	menu.add("3", "MOTD",              &motd);
	menu.add("4", "Banned users",      &banned_users);
	menu.add("i", "Server info",       &info);
	menu.add("q", "Exit",              &exit);

	menu.show();
}

void exit()
{
	writefln("\nA la prochaine...");
}

void admins()
{
	auto menu = new Menu("Admins (%d)".format(sdb.admins.length));

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
	const names = sdb.admins;

	writefln("\nAdmins (%d)...", names.length);
	foreach (name ; names) writefln("\t%s", name);

	admins();
}


void listen_port()
{
	uint port;
	try {port = sdb.get_config_value("port").to!ushort;} catch (ConvException) {}

	auto menu = new Menu(format("Listen port : %d", port));
	menu.add("1", "Change listen port", &set_listen_port);
	menu.add("q", "Return",             &main_menu);

	menu.show();
}

void set_listen_port()
{
	write("New listen port : ");

	const value = input.strip;
	uint port;
	try {port = value.to!uint;} catch (ConvException) {}
	if (port <= 0 || port > ushort.max) {
		writefln("Please enter a port in the range %d-%d", 1, 65535);
		set_listen_port();
		return;
	}

	sdb.set_config_value("port", port);
	listen_port();
}

void max_users()
{
	uint max_users;
	try {max_users = sdb.get_config_value("max_users").to!uint;} catch (ConvException) {}

	auto menu = new Menu(format("Max users allowed : %d", max_users));
	menu.add("1", "Change max users", &set_max_users);
	menu.add("q", "Return",           &main_menu);

	menu.show();
}

void set_max_users()
{
	write("Max users : ");

	const value = input.strip;
	uint num_users;
	try {
		num_users = value.to!uint;
	}
	catch (ConvException) {
		writefln("Please enter a valid number");
		set_max_users();
		return;
	}

	sdb.set_config_value("max_users", num_users);
	max_users();
}

void motd()
{
	auto menu = new Menu(
		format("Current message of the day :\n--\n%s\n--",
			sdb.get_config_value("motd"))
	);
	menu.add("1", "Change MOTD", &set_motd);
	menu.add("q", "Return",      &main_menu);

	menu.show();
}

void set_motd()
{
	writefln(
		"\nYou can use the following variables :"
		~ "\n\t%sversion%    : server version (" ~ VERSION ~ ")"
		~ "\n\t%users%       : number of connected users"
		~ "\n\t%username%    : name of the connecting user"
		~ "\n\t%version%     : version of the user's client software"
		~ "\n\nNew MOTD (end with a dot on a single line) :\n--"
	);

	string motd_template;

	do {
		const line = input.chomp;
		if (line.strip == ".")
			break;
		if (motd_template.length > 0) motd_template ~= "\n";
		motd_template ~= line;
	}
	while(true);

	sdb.set_config_value("motd", motd_template);
	motd();
}

void info()
{
	auto menu = new Menu(
		"Soulsetup for Soulfind %s (compiled on %s)".format(VERSION, __DATE__)
	);
	menu.info = "\t%d registered users".format(sdb.usernames.length);
	menu.info ~= "\n\t%d privileged users".format(sdb.usernames("privileges").length);
	menu.info ~= "\n\t%d banned users".format(sdb.usernames("banned").length);

	menu.add("1", "Recount", &info);
	menu.add("q", "Return", &main_menu);

	menu.show();
}

void banned_users()
{
	auto menu = new Menu("Banned users (%d)".format(sdb.usernames("banned").length));

	menu.add("1", "Ban user",          &ban_user);
	menu.add("2", "Unban user",        &unban_user);
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
	const users = sdb.usernames("banned");

	writefln("\nBanned users (%d)...", users.length);
	foreach (user ; users) writefln("\t%s", user);

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

	@trusted  // .keys doesn't work with @safe in old D versions
	string[] sorted_entry_indexes()
	{
		auto indexes = entries.keys;
		sort(indexes);
		return indexes;
	}

	void show()
	{
		writefln("\n%s\n", title);
		if (info.length > 0) writefln("%s\n", info);

		foreach (index ; sorted_entry_indexes)
			writefln("%s. %s", index, entries[index]);

		write("\nYour choice : ");
		const choice = input.strip;

		if (choice !in actions) {
			writefln(
				"Next time, try a number which has an action "
				~ "assigned to it..."
			);
			show();
			return;
		}
		actions[choice]();
	}
}
