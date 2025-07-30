// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup.setup;
@safe:

import core.time : days, Duration;
import soulfind.db : Sdb;
import soulfind.defines : default_db_filename, default_max_users, default_port,
                          VERSION;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.digest : digest, LetterCase, toHexString;
import std.digest.md : MD5;
import std.stdio : readln, StdioException, write, writefln, writeln;
import std.string : chomp, format, strip, toLower;
import std.system : os;

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
        this.db  = new Sdb(db_filename);
    }

    int show()
    {
        try main_menu(); catch (StdioException) {}
        return 0;
    }

    @trusted
    private string input()
    {
        return readln();
    }

    private void show_menu(string heading, MenuItem[] items)
    {
        do {
            writefln!("\n%s\n")(heading);

            foreach (item; items)
                writeln(format!("%s. %s")(item.index, item.label));

            write("\nYour choice : ");
            const choice = input.strip;

            foreach (item; items)
                if (choice == item.index) {
                    item.action();
                    return;
                }

            writeln(
                "Next time, try a number which has an action assigned to it..."
            );
        }
        while(true);
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
                MenuItem("4", "Registered users",  &registered_users),
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

        const username = input.strip;
        if (!db.user_exists(username)) {
            do {
                writefln(
                    "User %s is not registered. Do you really want to add "
                  ~ "them to the admin list? [y/n]", username
                );
                const response = input.strip.toLower;
                if (response == "y") {
                    db.add_admin(username);
                    break;
                } else if (response == "n") {
                    break;
                }
            }
            while(true);
        } else {
            db.add_admin(username);
        }
        admins();
    }

    private void del_admin()
    {
        write("Admin to remove : ");
        const username = input.strip;

        if (db.is_admin(username))
            db.del_admin(username);
        else
            writefln!("\nUser %s is not an admin")(username);

        admins();
    }

    private void list_admins()
    {
        const names = db.admins;

        Appender!string output;
        output ~= format!("\nAdmins (%d)...")(names.length);
        foreach (name ; names)
            output ~= format!(
                "\n\t%s (registered: %s)")(
                name, db.user_exists(name) ? "true" : "false"
            );

        writeln(output[]);
        admins();
    }


    private void listen_port()
    {
        ulong port;
        try
            port = db.get_config_value("port").to!ushort;
        catch (ConvException)
            port = default_port;

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
        ushort port;
        try {
            port = value.to!ushort;
        }
        catch (ConvException) {
            writefln!("Please enter a port in the range %d-%d")(1, ushort.max);
            set_listen_port();
            return;
        }

        db.set_config_value("port", port);
        listen_port();
    }

    private void max_users()
    {
        ulong max_users;
        try
            max_users = db.get_config_value("max_users").to!uint;
        catch (ConvException)
            max_users = default_max_users;

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

        Appender!string motd_template;
        auto first = true;
        do {
            const line = input.chomp;
            if (line.strip == ".")
                break;
            if (first) motd_template ~= "\n";
            motd_template ~= line;
            first = false;
        }
        while(true);

        db.set_config_value("motd", motd_template[]);
        motd();
    }

    private void server_info()
    {
        show_menu(
            format!(
                "Soulfind %s"
              ~ "\n\tOS: %s"
              ~ "\n\tCompiled with %s %s.%s on %s"
              ~ "\n\nStats:"
              ~ "\n\t%d registered users"
              ~ "\n\t%d privileged users"
              ~ "\n\t%d banned users")(
                VERSION, os, name, version_major, version_minor, __DATE__,
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

    private void registered_users()
    {
        show_menu(
            format!("Registered users (%d)")(db.num_users),
            [
                MenuItem("1", "Add user",              &add_user),
                MenuItem("2", "Show user info",        &user_info),
                MenuItem("3", "Change user password",  &change_user_password),
                MenuItem("4", "Unban user",            &unban_user),
                MenuItem("5", "Remove user",           &remove_user),
                MenuItem("6", "List registered users", &list_registered),
                MenuItem("7", "List privileged users", &list_privileged),
                MenuItem("8", "List banned users",     &list_banned),
                MenuItem("q", "Return",                &main_menu)
            ]
        );
    }

    private void add_user()
    {
        write("Username : ");
        const username = input.strip;

        if (db.user_exists(username)) {
            writefln!("\nUser %s is already registered")(username);
            registered_users();
            return;
        }

        write("Password : ");
        const password = input.strip;

        db.add_user(username, password);
        registered_users();
    }

    private void user_info()
    {
        write("Username : ");

        const username = input.strip;
        const now = Clock.currTime;
        const admin = db.is_admin(username);
        auto banned = "false";
        const banned_until = db.user_banned_until(username);
        auto privileged = "none";
        const privileged_until = db.user_privileged_until(username);
        const supporter = db.user_supporter(username);
        const stats = db.user_stats(username);

        if (banned_until == SysTime.fromUnixTime(long.max))
            banned = "forever";

        else if (banned_until > now)
            banned = format!("until %s")(banned_until.toSimpleString);

        if (privileged_until > now)
            privileged = format!("until %s")(privileged_until.toSimpleString);

        if (stats.exists) {
            writefln!(
                "\n%s"
              ~ "\n\tadmin: %s"
              ~ "\n\tbanned: %s"
              ~ "\n\tprivileged: %s"
              ~ "\n\tsupporter: %s"
              ~ "\n\tfiles: %s"
              ~ "\n\tdirs: %s"
              ~ "\n\tupload speed: %s")(
                username,
                admin,
                banned,
                privileged,
                supporter,
                stats.shared_files,
                stats.shared_folders,
                stats.upload_speed
            );
        }
        else
            writefln!("\nUser %s is not registered")(username);

        registered_users();
    }

    private void change_user_password()
    {
        write("User to change password of : ");
        const username = input.strip;

        if (db.user_exists(username)) {
            write("Enter new password : ");
            const password = input;

            db.user_update_password(username, password);
        }
        else
            writefln!("\nUser %s is not registered")(username);

        registered_users();
    }

    private void unban_user()
    {
        write("User to unban : ");
        const username = input.strip;

        if (db.user_banned(username))
            db.unban_user(username);
        else
            writefln!("\nUser %s is not banned")(username);

        registered_users();
    }

    private void remove_user()
    {
        write("User to remove : ");
        const username = input.strip;

        if (db.user_exists(username))
            db.del_user(username);
        else
            writefln!("\nUser %s is not registered")(username);

        registered_users();
    }

    private void list_registered()
    {
        const users = db.usernames;

        Appender!string output;
        output ~= format!("\nRegistered users (%d)...")(users.length);
        foreach (user ; users) output ~= format!("\n\t%s")(user);

        writeln(output[]);
        registered_users();
    }

    private void list_privileged()
    {
        const users = db.usernames("privileges", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= format!("\nPrivileged users (%d)...")(users.length);
        foreach (user ; users) {
            const privileged_until = db.user_privileged_until(user);
            output ~= format!("\n\t%s (until %s)")(
                user, privileged_until.toSimpleString
            );
        }

        writeln(output[]);
        registered_users();
    }

    private void list_banned()
    {
        const users = db.usernames("banned", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= format!("\nBanned users (%d)...")(users.length);
        foreach (user ; users) {
            const banned_until = db.user_banned_until(user);
            if (banned_until == SysTime.fromUnixTime(long.max))
                output ~= format!("\n\t%s (forever)")(user);
            else
                output ~= format!("\n\t%s (until %s)")(
                    user, banned_until.toSimpleString);
        }

        writeln(output[]);
        registered_users();
    }
}
