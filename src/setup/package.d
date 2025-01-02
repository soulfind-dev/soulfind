// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : default_db_filename, default_max_users, default_port,
                          exit_message, VERSION;
import std.conv : ConvException, to;
import std.exception : ifThrown;
import std.format : format;
import std.stdio : readf, readln, StdioException, write, writefln;
import std.string : chomp, strip;

Sdb sdb;

int run(string[] args)
{
    string db_filename = default_db_filename;

    if (args.length > 1) {
        if (args[1] == "--help" || args[1] == "-h") {
            writefln("Usage: %s [database_file]", args[0]);
            writefln(
                "\tdatabase_file: path to Soulfind's database (default: %s)",
                default_db_filename
            );
            return 0;
        }
        db_filename = args[1];
    }

    sdb = new Sdb(db_filename);
    try { main_menu(); } catch (StdioException) {}
    return 0;
}

@trusted
private string input()
{
    return readln();
}

private void main_menu()
{
    scope menu = new Menu("Soulfind %s configuration".format(VERSION));

    menu.add("0", "Admins",            &admins);
    menu.add("1", "Listen port",       &listen_port);
    menu.add("2", "Max users allowed", &max_users);
    menu.add("3", "MOTD",              &motd);
    menu.add("4", "Banned users",      &banned_users);
    menu.add("i", "Server info",       &info);
    menu.add("q", "Exit",              &exit);

    menu.show();
}

private void exit() {
    writefln("\n" ~ exit_message);
}

private void admins()
{
    scope menu = new Menu("Admins (%d)".format(sdb.admins.length));

    menu.add("1", "Add an admin",    &add_admin);
    menu.add("2", "Remove an admin", &del_admin);
    menu.add("3", "List admins",     &list_admins);
    menu.add("q", "Return",          &main_menu);

    menu.show();
}

private void add_admin()
{
    write("Admin to add : ");
    sdb.add_admin(input.strip);
    admins();
}

private void del_admin()
{
    write("Admin to remove : ");
    sdb.del_admin(input.strip);
    admins();
}

private void list_admins()
{
    const names = sdb.admins;

    writefln("\nAdmins (%d)...", names.length);
    foreach (name ; names) writefln("\t%s", name);

    admins();
}


private void listen_port()
{
    const port = sdb.get_config_value("port").to!ushort.ifThrown(
        default_port
    );
    scope menu = new Menu(format("Listen port : %d", port));
    menu.add("1", "Change listen port", &set_listen_port);
    menu.add("q", "Return",             &main_menu);

    menu.show();
}

private void set_listen_port()
{
    write("New listen port : ");

    const value = input.strip;
    const port = value.to!uint.ifThrown(0);
    if (port <= 0 || port > ushort.max) {
        writefln("Please enter a port in the range %d-%d", 1, 6_5535);
        set_listen_port();
        return;
    }

    sdb.set_config_value("port", port);
    listen_port();
}

private void max_users()
{
    const max_users = sdb.get_config_value("max_users").to!uint.ifThrown(
        default_max_users
    );
    scope menu = new Menu(format("Max users allowed : %d", max_users));
    menu.add("1", "Change max users", &set_max_users);
    menu.add("q", "Return",           &main_menu);

    menu.show();
}

private void set_max_users()
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

private void motd()
{
    scope menu = new Menu(
        format("Current message of the day :\n--\n%s\n--",
            sdb.get_config_value("motd"))
    );
    menu.add("1", "Change MOTD", &set_motd);
    menu.add("q", "Return",      &main_menu);

    menu.show();
}

private void set_motd()
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

private void info()
{
    scope menu = new Menu(
        "Soulsetup for Soulfind %s (compiled on %s)".format(VERSION, __DATE__)
    );
    menu.info = "\t%d registered users".format(sdb.num_users);
    menu.info ~= "\n\t%d privileged users".format(sdb.num_users("privileges"));
    menu.info ~= "\n\t%d banned users".format(sdb.num_users("banned"));

    menu.add("1", "Recount", &info);
    menu.add("q", "Return", &main_menu);

    menu.show();
}

private void banned_users()
{
    scope menu = new Menu("Banned users (%d)".format(sdb.num_users("banned")));

    menu.add("1", "Ban user",          &ban_user);
    menu.add("2", "Unban user",        &unban_user);
    menu.add("3", "List banned users", &list_banned);
    menu.add("q", "Return",            &main_menu);

    menu.show();
}

private void ban_user()
{
    write("User to ban : ");
    sdb.user_update_field(input.strip, "banned", 1);
    banned_users();
}

private void unban_user()
{
    write("User to unban : ");
    sdb.user_update_field(input.strip, "banned", 0);
    banned_users();
}

private void list_banned()
{
    const users = sdb.usernames("banned");

    writefln("\nBanned users (%d)...", users.length);
    foreach (user ; users) writefln("\t%s", user);

    banned_users();
}

private class Menu
{
    string                  title;
    string                  info;
    string[]                entries;
    void function()[string] actions;

    this(string title) scope
    {
        this.title = title;
    }

    void add(string index, string entry, void function() @safe action) scope
    {
        entries ~= "%s. %s".format(index, entry);
        actions[index] = action;
    }

    void show() scope
    {
        writefln("\n%s\n", title);
        if (info.length > 0) writefln("%s\n", info);

        foreach (entry ; entries)
            writefln(entry);

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
