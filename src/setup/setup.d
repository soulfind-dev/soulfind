// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup.setup;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : default_db_filename, default_max_users, default_port,
                          VERSION;
import std.compiler : name, version_major, version_minor;
import std.conv : ConvException, to;
import std.datetime : Clock;
import std.exception : ifThrown;
import std.format : format;
import std.stdio : readf, readln, StdioException, write, writefln, writeln;
import std.string : chomp, strip;
import std.system : endian, instructionSetArchitecture, os;

struct MenuItem
{
    string           index;
    string           label;
    void delegate()  action;
}

class Setup
{
    private Sdb db;


    this(string db_filename)
    {
        db = new Sdb(db_filename);
    }

    void show()
    {
        try { main_menu(); } catch (StdioException) {}
    }

    @trusted
    private string input()
    {
        return readln();
    }

    private void show_menu(string heading, MenuItem[] items)
    {
        while (true) {
            writefln!("\n%s\n")(heading);

            foreach (item; items)
            {
                writeln(format!("%s. %s")(item.index, item.label));
            }

            write("\nYour choice : ");
            const choice = input.strip;

            foreach (item; items)
            {
                if (choice == item.index)
                {
                    item.action();
                    return;
                }
            }

            writeln(
                "Next time, try a number which has an action assigned to it..."
            );
        }
    }

    private void main_menu()
    {
        show_menu(
            format!("Soulfind %s configuration")(VERSION),
            [
                MenuItem("0", "Admins",            &admins),
                MenuItem("1", "Listen port",       &listen_port),
                MenuItem("2", "Max users allowed", &max_users),
                MenuItem("3", "MOTD",              &motd),
                MenuItem("4", "Banned users",      &banned_users),
                MenuItem("i", "Server info",       &server_info),
                MenuItem("q", "Exit",              &exit)
            ]
        );
    }

    private void exit() {}

    private void admins()
    {
        show_menu(
            format!("Admins (%d)")(db.admins.length),
            [
                MenuItem("1", "Add an admin",    &add_admin),
                MenuItem("2", "Remove an admin", &del_admin),
                MenuItem("3", "List admins",     &list_admins),
                MenuItem("q", "Return",          &main_menu)
            ]
        );
    }

    private void add_admin()
    {
        write("Admin to add : ");
        db.add_admin(input.strip);
        admins();
    }

    private void del_admin()
    {
        write("Admin to remove : ");
        db.del_admin(input.strip);
        admins();
    }

    private void list_admins()
    {
        const names = db.admins;

        writefln!("\nAdmins (%d)...")(names.length);
        foreach (name ; names) writefln!("\t%s")(name);

        admins();
    }


    private void listen_port()
    {
        const port = db.get_config_value("port")
            .to!ushort
            .ifThrown(default_port);

        show_menu(
            format!("Listen port : %d")(port),
            [
                MenuItem("1", "Change listen port", &set_listen_port),
                MenuItem("q", "Return",             &main_menu)
            ]
        );
    }

    private void set_listen_port()
    {
        write("New listen port : ");

        const value = input.strip;
        const port = value.to!uint.ifThrown(0);
        if (port <= 0 || port > ushort.max) {
            writefln!("Please enter a port in the range %d-%d")(1, 65535);
            set_listen_port();
            return;
        }

        db.set_config_value("port", port);
        listen_port();
    }

    private void max_users()
    {
        const max_users = db.get_config_value("max_users")
            .to!uint
            .ifThrown(default_max_users);

        show_menu(
            format!("Max users allowed : %d")(max_users),
            [
                MenuItem("1", "Change max users", &set_max_users),
                MenuItem("q", "Return",           &main_menu)
            ]
        );
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
            writeln("Please enter a valid number");
            set_max_users();
            return;
        }

        db.set_config_value("max_users", num_users);
        max_users();
    }

    private void motd()
    {
        show_menu(
            format!("Current message of the day :\n--\n%s\n--")(
                    db.get_config_value("motd")),
            [
                MenuItem("1", "Change MOTD", &set_motd),
                MenuItem("q", "Return",      &main_menu)
            ]
        );
    }

    private void set_motd()
    {
        writefln!(
            "\nYou can use the following variables :"
          ~ "\n\t%%sversion%%    : server version (%s)"
          ~ "\n\t%%users%%       : number of connected users"
          ~ "\n\t%%username%%    : name of the connecting user"
          ~ "\n\t%%version%%     : version of the user's client software"
          ~ "\n\nNew MOTD (end with a dot on a single line) :\n--")(
             VERSION
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

        db.set_config_value("motd", motd_template);
        motd();
    }

    private void server_info()
    {
        show_menu(
            format!(
                "Soulfind %s"
              ~ "\n\tOS: %s"
              ~ "\n\tArch: %s (%s)"
              ~ "\n\tCompiled with %s %s.%s on %s"
              ~ "\n\nStats:"
              ~ "\n\t%d registered users"
              ~ "\n\t%d privileged users"
              ~ "\n\t%d banned users")(
                VERSION, os, instructionSetArchitecture, endian, name,
                version_major, version_minor, __DATE__,
                db.num_users,
                db.num_users("privileges", Clock.currTime.toUnixTime),
                db.num_users("banned", Clock.currTime.toUnixTime)
            ),
            [
                MenuItem("1", "Recount", &server_info),
                MenuItem("q", "Return", &main_menu)
            ]
        );
    }

    private void banned_users()
    {
        show_menu(
            format!("Banned users (%d)")(
                db.num_users("banned", Clock.currTime.toUnixTime)
            ),
            [
                MenuItem("1", "Ban user forever",  &ban_user),
                MenuItem("2", "Unban user",        &unban_user),
                MenuItem("3", "List banned users", &list_banned),
                MenuItem("q", "Return",            &main_menu)
            ]
        );
    }

    private void ban_user()
    {
        write("User to ban : ");
        const username = input.strip;

        if (db.user_exists(username))
            db.user_update_field(username, "banned", long.max);
        else
            writefln!("\nUser %s is not registered")(username);

        banned_users();
    }

    private void unban_user()
    {
        write("User to unban : ");
        db.user_update_field(input.strip, "banned", 0);
        banned_users();
    }

    private void list_banned()
    {
        const users = db.usernames("banned", Clock.currTime.toUnixTime);

        writefln!("\nBanned users (%d)...")(users.length);
        foreach (user ; users) writefln!("\t%s")(user);

        banned_users();
    }
}
