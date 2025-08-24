// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup.setup;
@safe:

import core.time : days, Duration;
import soulfind.db : Sdb;
import soulfind.defines : VERSION;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.conv : ConvException, text, to;
import std.datetime.systime : Clock, SysTime;
import std.digest : digest, LetterCase, toHexString;
import std.digest.md : MD5;
import std.stdio : readln, StdioException, write, writeln;
import std.string : chomp, strip, toLower;
import std.system : os;

struct MenuItem
{
    string           index;
    string           label;
    void delegate()  action;
}

final class Setup
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
            writeln("\n", heading, "\n");

            foreach (ref item; items)
                writeln(item.index, ". ", item.label);

            write("\nYour choice : ");
            const choice = input.strip;

            if (choice is null) {
                writeln("\nNo terminal input available, exiting...");
                return;
            }

            foreach (ref item; items)
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
            text("Soulfind ", VERSION, " configuration"),
            [
                MenuItem("0", "Admins",            &admins),
                MenuItem("1", "Listen port",       &listen_port),
                MenuItem("2", "Max users allowed", &max_users),
                MenuItem("3", "Private mode",      &private_mode),
                MenuItem("4", "MOTD",              &motd),
                MenuItem("5", "Registered users",  &registered_users),
                MenuItem("i", "Server info",       &server_info),
                MenuItem("q", "Exit",              &exit)
            ]
        );
    }

    private void exit() {}

    private void admins()
    {
        show_menu(
            text("Admins (", db.admins.length, ")"),
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
                writeln(
                    "User ", username, " is not registered. Do you really ",
                    "want to add them to the admin list? [y/n]"
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
            writeln("\nUser ", username, " is not an admin");

        admins();
    }

    private void list_admins()
    {
        const names = db.admins;

        Appender!string output;
        output ~= text("\nAdmins (", names.length, ")...");
        foreach (ref name ; names)
            output ~= text(
                "\n\t", name, " (registered: ",
                db.user_exists(name) ? "true" : "false", ")"
            );

        writeln(output[]);
        admins();
    }


    private void listen_port()
    {
        show_menu(
            text("Listen port : ", db.server_port),
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
            writeln("Please enter a port in the range ", 1, "-", ushort.max);
            set_listen_port();
            return;
        }

        db.set_server_port(port);
        listen_port();
    }

    private void private_mode()
    {
        show_menu(
            text(
                "Private mode : ",
                db.server_private_mode ? "enabled" : "disabled",
                "\n\nPrivate mode disables new user registrations from the",
                " client."
            ),
            [
                MenuItem("1", "Toggle private mode", &toggle_private_mode),
                MenuItem("q", "Return",              &main_menu)
            ]
        );
    }

    private void toggle_private_mode()
    {
        db.set_server_private_mode(!db.server_private_mode);
        private_mode();
    }

    private void max_users()
    {
        show_menu(
            text("Max users allowed : ", db.server_max_users),
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

        db.set_server_max_users(num_users);
        max_users();
    }

    private void motd()
    {
        show_menu(
            text("Current message of the day :\n--\n", db.server_motd, "\n--"),
            [
                MenuItem("1", "Change MOTD", &set_motd),
                MenuItem("q", "Return",      &main_menu)
            ]
        );
    }

    private void set_motd()
    {
        writeln(
            "\nYou can use the following variables :",
            "\n\t%%sversion%%    : server version (", VERSION, ")",
            "\n\t%%users%%       : number of connected users",
            "\n\t%%username%%    : name of the connecting user",
            "\n\t%%version%%     : version of the user's client software",
            "\n\nNew MOTD (end with a dot on a single line) :\n--"
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

        db.set_server_motd(motd_template[]);
        motd();
    }

    private void server_info()
    {
        show_menu(
            text(
                "Soulfind ", VERSION,
                "\n\tCompiled with ", name, " ",
                version_major, ".", version_minor, " for ", os,
                "\n\nStats:",
                "\n\t", db.num_users, " registered users",
                "\n\t", db.num_users("privileges", Clock.currTime.toUnixTime),
                " privileged users",
                "\n\t", db.num_users("banned", Clock.currTime.toUnixTime),
                " banned users"
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
            text("Registered users (", db.num_users, ")"),
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
        string username;
        do {
            write("Username : ");
            username = input.strip;
            if (username.length > 0)
                break;
            writeln("Please enter a username");
        }
        while(true);

        if (db.user_exists(username)) {
            writeln("\nUser ", username, " is already registered");
            registered_users();
            return;
        }

        string password;
        do {
            write("Password : ");
            password = input.chomp;
            if (password.length > 0)
                break;
            writeln("Please enter a password");
        }
        while(true);

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
        auto privileged = "false";
        const privileged_until = db.user_privileged_until(username);
        const supporter = privileged_until.stdTime > 0;
        const stats = db.user_stats(username);

        if (banned_until == SysTime.fromUnixTime(long.max))
            banned = "forever";

        else if (banned_until > now)
            banned = text("until ", banned_until.toSimpleString);

        if (privileged_until > now)
            privileged = text("until ", privileged_until.toSimpleString);

        if (stats.exists) {
            writeln(
                "\n", username,
                "\n\tadmin: ", admin,
                "\n\tbanned: ", banned,
                "\n\tprivileged: ", privileged,
                "\n\tsupporter: ", supporter,
                "\n\tfiles: ", stats.shared_files,
                "\n\tdirs: ", stats.shared_folders,
                "\n\tupload speed: ", stats.upload_speed
            );
        }
        else
            writeln("\nUser ", username, " is not registered");

        registered_users();
    }

    private void change_user_password()
    {
        write("User to change password of : ");
        const username = input.strip;

        if (db.user_exists(username)) {
            string password;
            do {
                write("Enter new password : ");
                password = input.chomp;
                if (password.length > 0)
                    break;
                writeln("Please enter a password");
            }
            while(true);

            db.user_update_password(username, password);
        }
        else
            writeln("\nUser ", username, " is not registered");

        registered_users();
    }

    private void unban_user()
    {
        write("User to unban : ");
        const username = input.strip;

        if (db.user_banned_until(username).stdTime > 0)
            db.unban_user(username);
        else
            writeln("\nUser ", username, " is not banned");

        registered_users();
    }

    private void remove_user()
    {
        write("User to remove : ");
        const username = input.strip;

        if (db.user_exists(username))
            db.del_user(username);
        else
            writeln("\nUser ", username, " is not registered");

        registered_users();
    }

    private void list_registered()
    {
        const names = db.usernames;

        Appender!string output;
        output ~= text("\nRegistered users (", names.length, ")...");
        foreach (ref name ; names) output ~= text("\n\t", name);

        writeln(output[]);
        registered_users();
    }

    private void list_privileged()
    {
        const names = db.usernames("privileges", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= text("\nPrivileged users (", names.length, ")...");
        foreach (ref name ; names) {
            const privileged_until = db.user_privileged_until(name);
            output ~= text(
            	"\n\t", name, " (until ", privileged_until.toSimpleString, ")"
            );
        }

        writeln(output[]);
        registered_users();
    }

    private void list_banned()
    {
        const names = db.usernames("banned", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= text("\nBanned users (", names.length, ")...");
        foreach (ref name ; names) {
            const banned_until = db.user_banned_until(name);
            if (banned_until != SysTime.fromUnixTime(long.max))
                output ~= text(
                    "\n\t", name, " (until ", banned_until.toSimpleString, ")"
                );
            else
                output ~= text("\n\t", name, " (forever)");
        }

        writeln(output[]);
        registered_users();
    }
}
