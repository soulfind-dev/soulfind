// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.setup.setup;
@safe:

import soulfind.db : Sdb;
import soulfind.defines : blue, bold, norm, pbkdf2_iterations, red,
                          SearchFilterType, VERSION;
import soulfind.pwhash : create_salt, hash_password;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.conv : ConvException, text, to;
import std.datetime : Clock, days, Duration, SysTime;
import std.stdio : readln, StdioException, write, writeln;
import std.string : chomp, join, split, strip, toLower;

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
        writeln("\n", heading, "\n");

        foreach (ref item; items)
            writeln(item.index, ". ", item.label);

        while (true) {
            write("\n>", norm, " ");
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

            write("\nTry a number which has an action assigned to it...");
        }
    }

    private void main_menu()
    {
        show_menu(
            text(bold, "Soulfind server management tool", norm),
            [
                MenuItem("1", "Admins",            &admins),
                MenuItem("2", "Registered users",  &registered_users),
                MenuItem("3", "Listening port",    &listening_port),
                MenuItem("4", "Private mode",      &private_mode),
                MenuItem("5", "Max users allowed", &max_users),
                MenuItem("6", "MOTD",              &motd),
                MenuItem("7", "Search filters",    &search_filters),
                MenuItem("i", "Server info",       &server_info),
                MenuItem("q", "Exit",              &exit)
            ]
        );
    }

    private void exit() {}

    private void admins()
    {
        show_menu(
            text(bold, "Admins (", db.num_users("admin"), ")", norm),
            [
                MenuItem("1", "Add/renew an admin", &add_admin),
                MenuItem("2", "Remove an admin",    &del_admin),
                MenuItem("3", "List admins",        &list_admins),
                MenuItem("q", "Return",             &main_menu)
            ]
        );
    }

    private void add_admin()
    {
        write("\nAdmin to add: ");

        const username = input.strip;
        if (!db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is not registered");
            admins();
            return;
        }

        Duration duration;
        while (true) {
            try {
                write("Number of days of admin status: ");
                const value = input.strip.to!ulong;
                const limit = ushort.max;
                duration = (value > limit ? limit : value).days;
                break;
            }
            catch (ConvException) {
                writeln("\nInvalid number or too many days");
            }
        }

        db.add_admin(username, duration);
        writeln(
            "\nMade ", blue, username, norm, " an admin until ",
            db.admin_until(username).toSimpleString
        );
        admins();
    }

    private void del_admin()
    {
        write("\nAdmin to remove: ");
        const username = input.strip;

        if (db.admin_until(username) > SysTime()) {
            db.del_admin(username);
            writeln("\nUser ", blue, username, norm, " is no longer an admin");
        }
        else
            writeln("\nUser ", red, username, norm, " is not an admin");

        admins();
    }

    private void list_admins()
    {
        const names = db.usernames("admin");
        const now = Clock.currTime;

        Appender!string output;
        output ~= text("\n", bold, "Admins: ", norm);
        foreach (ref name ; names) {
            const admin_until = db.admin_until(name);
            output ~= "\n\t";
            output ~= name;

            if (admin_until > now)
                output ~= text(" (until ", admin_until.toSimpleString, ")");
            else
                output ~= text(" (expired)");
        }

        writeln(output[]);
        admins();
    }


    private void listening_port()
    {
        show_menu(
            text(bold, "Listening port: ", blue, db.server_port, norm),
            [
                MenuItem("1", "Change listening port", &set_listening_port),
                MenuItem("q", "Return",                &main_menu)
            ]
        );
    }

    private void set_listening_port()
    {
        write("\nNew listening port: ");

        const value = input.strip;
        ushort port;
        try {
            port = value.to!ushort;
        }
        catch (ConvException) {
            writeln("\nPlease enter a port in the range ", 1, "-", ushort.max);
            set_listening_port();
            return;
        }

        db.set_server_port(port);
        listening_port();
    }

    private void private_mode()
    {
        show_menu(
            text(
                bold, "Private mode: ",
                db.server_private_mode ?
                text(
                    blue, "enabled", norm,
                    "\n\tNot accepting user registrations."
                ) :
                text(
                    red, "disabled", norm,
                    "\n\tAccepting user registrations."
                )
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
            text(bold, "Max users allowed: ", blue, db.server_max_users, norm),
            [
                MenuItem("1", "Change max users", &set_max_users),
                MenuItem("q", "Return",           &main_menu)
            ]
        );
    }

    private void set_max_users()
    {
        write("\nNew max users allowed: ");

        const value = input.strip;
        uint num_users;
        try {
            num_users = value.to!uint;
        }
        catch (ConvException) {
            writeln("\nPlease enter a valid number");
            set_max_users();
            return;
        }

        db.set_server_max_users(num_users);
        max_users();
    }

    private void motd()
    {
        show_menu(
            text(bold, "Message of the day:", norm, "\n", db.server_motd),
            [
                MenuItem("1", "Change MOTD", &set_motd),
                MenuItem("q", "Return",      &main_menu)
            ]
        );
    }

    private void set_motd()
    {
        writeln(
            "\nAvailable variables:",
            "\n\t%%sversion%% - server version (", VERSION, ")",
            "\n\t%%users%%    - number of connected users",
            "\n\t%%username%% - name of the connecting user",
            "\n\t%%version%%  - version of the user's client software",
            "\n\nNew MOTD (end with a dot on a single line):"
        );

        Appender!string motd_template;
        auto first = true;
        while (true) {
            const line = input.chomp;
            if (line.strip == ".")
                break;
            if (first) motd_template ~= "\n";
            motd_template ~= line;
            first = false;
        }

        db.set_server_motd(motd_template[]);
        motd();
    }

    private void search_filters()
    {
        const server = SearchFilterType.server;
        const client = SearchFilterType.client;

        show_menu(
            text(
                bold, "Filtered search phrases", norm,
                "\n\tserver-side: ", db.num_search_filters!server,
                "\n\tclient-side: ", db.num_search_filters!client
            ),
            [
                MenuItem("1", "Filter server phrase",   &add_filter!server),
                MenuItem("2", "Filter client phrase",   &add_filter!client),
                MenuItem("3", "Unfilter server phrase", &del_filter!server),
                MenuItem("4", "Unfilter client phrase", &del_filter!client),
                MenuItem("5", "List server phrases",    &list_filters!server),
                MenuItem("6", "List client phrases",    &list_filters!client),
                MenuItem("q", "Return",                 &main_menu)
            ]
        );
    }

    private void add_filter(SearchFilterType type)()
    {
        const stype = type == SearchFilterType.server ? "server" : "client";
        write("\nPhrase to filter ", stype, "-side: ");
        const phrase = input.split.join(" ").toLower;

        if (db.is_search_phrase_filtered!type(phrase)) {
            writeln(
                "\nPhrase ", red, phrase, norm, " is already filtered ",
                stype, "-side"
            );
            search_filters();
            return;
        }

        db.filter_search_phrase!type(phrase);

        writeln("\nFiltered phrase ", blue, phrase, norm, " ", stype, "-side");
        search_filters();
    }

    private void del_filter(SearchFilterType type)()
    {
        const stype = type == SearchFilterType.server ? "server" : "client";
        write("\nPhrase to unfilter ", stype, "-side: ");
        const phrase = input.split.join(" ").toLower;

        if (db.is_search_phrase_filtered!type(phrase)) {
            db.unfilter_search_phrase!type(phrase);
            writeln(
                "\nUnfiltered phrase ", blue, phrase, norm, " ", stype, "-side"
            );
        }
        else
            writeln(
                "\nPhrase ", red, phrase, norm, " is not filtered ",
                stype, "-side"
            );

        search_filters();
    }

    private void list_filters(SearchFilterType type)()
    {
        const phrases = db.search_filters!type;

        Appender!string output;
        output ~= text(
            "\n", bold, "Filtered phrases (",
            type == SearchFilterType.server ? "server" : "client",
            "-side):", norm
        );

        foreach (phrase ; phrases) {
            output ~= "\n\t";
            output ~= phrase;
        }

        writeln(output[]);
        search_filters();
    }

    private void registered_users()
    {
        const now = Clock.currTime.toUnixTime;
        show_menu(
            text(
                bold, "Registered users (", db.num_users, ")", norm,
                "\n\tprivileged: ", db.num_users("privileges", now),
                "\n\tbanned: ", db.num_users("banned", now)
            ),
            [
                MenuItem("1",  "Add user",              &add_user),
                MenuItem("2",  "Change user password",  &change_user_password),
                MenuItem("3",  "Show user info",        &user_info),
                MenuItem("4",  "Remove user",           &del_user),
                MenuItem("5",  "Add privileges",        &add_privileges),
                MenuItem("6",  "Remove privileges",     &del_privileges),
                MenuItem("7",  "Ban user",              &ban_user),
                MenuItem("8",  "Unban user",            &unban_user),
                MenuItem("9",  "List registered users", &list_registered),
                MenuItem("10", "List privileged users", &list_privileged),
                MenuItem("11", "List banned users",     &list_banned),
                MenuItem("q",  "Return",                &main_menu)
            ]
        );
    }

    private void add_user()
    {
        write("\nUsername: ");
        const username = input.strip;

        if (username.length == 0) {
            writeln("\nNo username provided");
            registered_users();
            return;
        }

        if (db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is already registered");
            registered_users();
            return;
        }

        string password;
        while (true) {
            write("Password: ");
            password = input.chomp;
            if (password.length > 0)
                break;
            writeln("\nPlease enter a password");
        }

        const salt = create_salt();
        const hash = hash_password(password, salt, pbkdf2_iterations);
        db.add_user(username, hash);

        writeln("\nAdded user ", blue, username, norm);
        registered_users();
    }

    private void change_user_password()
    {
        write("\nUser to change password of: ");
        const username = input.strip;

        if (!db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is not registered");
            registered_users();
            return;
        }

        string password;
        while (true) {
            write("New password: ");
            password = input.chomp;
            if (password.length > 0)
                break;
            writeln("\nPlease enter a password");
        }

        const salt = create_salt();
        const hash = hash_password(password, salt, pbkdf2_iterations);
        db.user_update_password(username, hash);

        writeln("\nChanged user ", blue, username, norm, "'s password");
        registered_users();
    }

    private void user_info()
    {
        write("\nUsername: ");

        const username = input.strip;
        const now = Clock.currTime;
        auto admin = "no";
        const admin_until = db.admin_until(username);
        auto banned = "no";
        const banned_until = db.user_banned_until(username);
        auto privileged = "no";
        const privileged_until = db.user_privileged_until(username);
        const supporter = (privileged_until > SysTime()) ? "yes" : "no";
        const stats = db.user_stats(username);

        if (admin_until > now)
            admin = text("until ", admin_until.toSimpleString);

        if (banned_until == SysTime.max)
            banned = "forever";

        else if (banned_until > now)
            banned = text("until ", banned_until.toSimpleString);

        if (privileged_until > now)
            privileged = text("until ", privileged_until.toSimpleString);

        if (stats.exists) {
            writeln(
                "\n", bold, username, norm,
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
            writeln("\nUser ", red, username, norm, " is not registered");

        registered_users();
    }

    private void del_user()
    {
        write("\nUser to remove: ");
        const username = input.strip;

        if (db.user_exists(username)) {
            db.del_user(username);
            writeln("\nRemoved user ", blue, username, norm);
        }
        else
            writeln("\nUser ", red, username, norm, " is not registered");

        registered_users();
    }

    private void add_privileges()
    {
        write("\nUser to grant privileges: ");
        const username = input.strip;

        if (!db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is not registered");
            registered_users();
            return;
        }

        Duration duration;
        while (true) {
            try {
                write("Number of days to add: ");
                const value = input.strip.to!ulong;
                const limit = ushort.max;
                duration = (value > limit ? limit : value).days;
                break;
            }
            catch (ConvException) {
                writeln("\nInvalid number or too many days");
            }
        }

        db.add_user_privileges(username, duration);

        writeln(
            "Added ", duration.total!"days".days.toString,
            " of privileges to user ", blue, username, norm
        );
        registered_users();
    }

    private void del_privileges()
    {
        write("\nUser to remove privileges from: ");
        const username = input.strip;

        if (!db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is not registered");
            registered_users();
            return;
        }

        Duration duration;
        while (true) {
            write("Number of days to remove (empty = all): ");
            const user_input = input.strip;

            if (user_input.length == 0) {
                duration = Duration.max;
                break;
            }

            try {
                const value = user_input.to!ulong;
                const limit = ushort.max;
                duration = (value > limit ? limit : value).days;
                break;
            }
            catch (ConvException) {
                writeln("\nInvalid number or too many days");
            }
        }

        db.remove_user_privileges(username, duration);

        if (duration == Duration.max)
            writeln("Removed all privileges from user ", blue, username, norm);
        else
            writeln(
                "Removed ", duration.total!"days".days.toString,
                " of privileges from user ", blue, username, norm
            );

        registered_users();
    }

    private void ban_user()
    {
        write("User to ban: ");
        const username = input.strip;

        if (!db.user_exists(username)) {
            writeln("\nUser ", red, username, norm, " is not registered");
            registered_users();
            return;
        }

        Duration banned_until;
        while (true) {
            write("Number of days to ban user (empty = forever): ");
            const duration = input.strip;

            if (duration.length == 0) {
                banned_until = Duration.max;
                break;
            }

            try {
                banned_until = duration.to!uint.days;
                break;
            }
            catch (ConvException) {
                writeln("\nInvalid number or too many days");
            }
        }

        db.ban_user(username, banned_until);

        if (banned_until == Duration.max)
            writeln("\nBanned user ", blue, username, norm, " forever");
        else
            writeln(
                "\nBanned user ", blue, username, norm, " until ",
                banned_until
            );

        registered_users();
    }

    private void unban_user()
    {
        write("\nUser to unban: ");
        const username = input.strip;

        if (db.user_banned_until(username) > SysTime()) {
            db.unban_user(username);
            writeln("\nUnbanned user ", blue, username, norm);
        }
        else
            writeln("\nUser ", red, username, norm, " is not banned");

        registered_users();
    }

    private void list_registered()
    {
        const names = db.usernames;

        Appender!string output;
        output ~= text("\n", bold, "Registered users:", norm);

        foreach (ref name ; names) {
            output ~= "\n\t";
            output ~= name;
        }

        writeln(output[]);
        registered_users();
    }

    private void list_privileged()
    {
        const names = db.usernames("privileges", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= text("\n", bold, "Privileged users:", norm);

        foreach (ref name ; names) {
            const privileged_until = db.user_privileged_until(name);
            output ~= "\n\t";
            output ~= name;
            output ~= text(" (until ", privileged_until.toSimpleString, ")");
        }

        writeln(output[]);
        registered_users();
    }

    private void list_banned()
    {
        const names = db.usernames("banned", Clock.currTime.toUnixTime);

        Appender!string output;
        output ~= text("\n", bold, "Banned users: ", norm);

        foreach (ref name ; names) {
            const banned_until = db.user_banned_until(name);
            if (banned_until != SysTime.max) {
                output ~= "\n\t";
                output ~= name;
                output ~= text(" (until ", banned_until.toSimpleString, ")");
            }
            else {
                output ~= "\n\t";
                output ~= name;
                output ~= " (forever)";
            }
        }

        writeln(output[]);
        registered_users();
    }

    private void server_info()
    {
        writeln(
            "\n", red, "\&hearts;", norm, " ", bold, "Soulfind ", VERSION,
            norm, "\n\tCompiled with ", name, " ",
            version_major, ".", version_minor,
            "\n\tUsing SQLite ", db.sqlite_version
        );
        main_menu();
    }
}
