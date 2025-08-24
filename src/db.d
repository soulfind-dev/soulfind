// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import core.time : days, Duration;
import soulfind.defines : blue, default_max_users, default_motd, default_port,
                          default_private_mode, log_db, log_user, norm;
import std.array : Appender;
import std.conv : ConvException, text, to;
import std.datetime.systime : Clock, SysTime;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.stdio : writeln;
import std.string : fromStringz, join, replace, toStringz;

extern (C) {
    // Manual definitions due to etc.c.sqlite3 bindings being out of date, or
    // missing in certain GDC versions.
    // https://github.com/dlang/phobos/blob/HEAD/etc/c/sqlite3.d

    enum
    {
        SQLITE_OK                       = 0,
        SQLITE_ROW                      = 100,
        SQLITE_DONE                     = 101
    }

    enum
    {
        SQLITE_CONFIG_SINGLETHREAD      = 1
    }

    enum
    {
        SQLITE_DBCONFIG_ENABLE_TRIGGER  = 1003,
        SQLITE_DBCONFIG_DEFENSIVE       = 1010,
        SQLITE_DBCONFIG_ENABLE_VIEW     = 1015,
        SQLITE_DBCONFIG_TRUSTED_SCHEMA  = 1017
    }

    struct sqlite3;
    int sqlite3_initialize();
    int sqlite3_shutdown();
    int sqlite3_config(int, ...);
    int sqlite3_db_config(sqlite3*, int op, ...);

    int sqlite3_open(const(char)*filename, sqlite3 **ppDb);
    int sqlite3_close(sqlite3 *);
    int sqlite3_extended_errcode(sqlite3 *db);
    const(char)* sqlite3_errmsg(sqlite3*);
    const(char)* sqlite3_errstr(int);

    struct sqlite3_stmt;
    int sqlite3_prepare_v2(
        sqlite3 *db, const(char)*zSql, int nByte, sqlite3_stmt **ppStmt,
        const(char*)*pzTail
    );
    int sqlite3_bind_null(sqlite3_stmt*, int);
    int sqlite3_bind_text(
        sqlite3_stmt*, int, const char*, int n, void function (void*)
    );
    int sqlite3_column_count(sqlite3_stmt *pStmt);
    int sqlite3_step(sqlite3_stmt*);
    const (char)* sqlite3_column_text(sqlite3_stmt*, int iCol);
    int sqlite3_finalize(sqlite3_stmt *pStmt);
}

struct SdbUserStats
{
    string  username;
    bool    exists;
    uint    upload_speed;
    uint    shared_files;
    uint    shared_folders;

    bool    updating_speed;
    bool    updating_shared;
}

final class SdbException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

final class Sdb
{
    sqlite3* db;

    const users_table   = "users";
    const admins_table  = "admins";
    const config_table  = "config";


    this(string filename)
    {
        if (log_db) writeln("DB: Using database: ", filename);

        // Soulfind is single-threaded. Disable SQLite mutexes for a slight
        // performance improvement.
        config(SQLITE_CONFIG_SINGLETHREAD);

        initialize();
        open(filename);

        // https://www.sqlite.org/security.html
        db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1);
        db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0);
        db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0);
        db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0);

        query("PRAGMA secure_delete = ON;");

        const users_sql = text(
            "CREATE TABLE IF NOT EXISTS ", users_table,
            "(username TEXT PRIMARY KEY,",
            " password TEXT NOT NULL,",
            " speed INTEGER,",
            " files INTEGER,",
            " folders INTEGER,",
            " banned INTEGER,",
            " privileges INTEGER",
            ") WITHOUT ROWID;"
        );

        const admins_sql = text(
            "CREATE TABLE IF NOT EXISTS ", admins_table,
            "(username TEXT PRIMARY KEY,",
            " level INTEGER NOT NULL",
            ") WITHOUT ROWID;"
        );

        foreach (ref problem ; query("PRAGMA integrity_check;"))
            if (log_db) writeln("DB: Check [", problem[0], "]");

        query("PRAGMA optimize=0x10002;");  // =all tables
        query(users_sql);
        query(admins_sql);
        init_config();
    }

    ~this()
    {
        if (log_db) writeln("DB: Shutting down...");
        close();
        shutdown();
    }

    private void init_config()
    {
        const sql = text(
            "CREATE TABLE IF NOT EXISTS ", config_table,
            "(option TEXT PRIMARY KEY,",
            " value",
            ") WITHOUT ROWID;"
        );
        query(sql);

        if (get_config_value("port") is null)
            set_server_port(default_port);

        if (get_config_value("max_users") is null)
            set_server_max_users(default_max_users);

        if (get_config_value("private_mode") is null)
            set_server_private_mode(default_private_mode);

        if (get_config_value("motd") is null)
            set_server_motd(default_motd);
    }

    private string get_config_value(string option)
    {
        const sql = text(
            "SELECT value FROM ", config_table, " WHERE option = ?;"
        );
        const res = query(sql, [option]);
        string value;

        if (res.length > 0)
            value = res[0][0];

        return value;
    }

    private void set_config_value(string option, string value)
    {
        const sql = text(
            "REPLACE INTO ", config_table, "(option, value) VALUES(?, ?);"
        );
        query(sql, [option, value]);

        if (log_db) writeln(
            "DB: Updated config value ", option, " to ", value
        );
    }

    ushort server_port()
    {
        ushort port = default_port;
        const config_value = get_config_value("port");

        if (config_value !is null)
            try port = config_value.to!ushort; catch (ConvException) {}

        return port;
    }

    void set_server_port(ushort port)
    {
        set_config_value("port", port.text);
    }

    uint server_max_users()
    {
        uint max_users = default_max_users;
        const config_value = get_config_value("max_users");

        if (config_value !is null)
            try max_users = config_value.to!uint; catch (ConvException) {}

        return max_users;
    }

    void set_server_max_users(uint num_users)
    {
        set_config_value("max_users", num_users.text);
    }

    bool server_private_mode()
    {
        bool private_mode = default_private_mode;
        const config_value = get_config_value("private_mode");

        if (config_value !is null)
            try private_mode = cast(bool) config_value.to!ubyte;
            catch (ConvException) {}

        return private_mode;
    }

    void set_server_private_mode(bool private_mode)
    {
        set_config_value("private_mode", private_mode.to!ubyte.text);
    }

    string server_motd()
    {
        string motd = default_motd;
        const config_value = get_config_value("motd");

        if (config_value !is null)
            motd = config_value;

        return motd;
    }

    void set_server_motd(string motd)
    {
        set_config_value("motd", motd);
    }

    void add_admin(string username)
    {
        const sql = text(
            "REPLACE INTO ", admins_table, "(username, level) VALUES(?, ?);"
        );
        const level = 0;
        query(sql, [username, level.text]);

        if (log_user) writeln("Added new admin ", blue, username, norm);
    }

    void del_admin(string username)
    {
        const sql = text("DELETE FROM ", admins_table, " WHERE username = ?;");
        query(sql, [username]);

        if (log_user) writeln("Removed admin ", blue, username, norm);
    }

    string[] admins()
    {
        const sql = text("SELECT username FROM ", admins_table, ";");
        Appender!(string[]) admins;
        foreach (ref record ; query(sql)) admins ~= record[0];
        return admins[];
    }

    bool is_admin(string username)
    {
        const sql = text(
            "SELECT 1 FROM ", admins_table, " WHERE username = ?;"
        );
        return query(sql, [username]).length > 0;
    }

    private string hash_password(string password)
    {
        return digest!MD5(password).toHexString!(LetterCase.lower).idup;
    }

    void add_user(string username, string password)
    {
        const sql = text(
            "INSERT INTO ", users_table, "(username, password) VALUES(?, ?);"
        );
        const hash = hash_password(password);

        query(sql, [username, hash]);
        query("PRAGMA optimize;");

        if (log_user) writeln("Added new user ", blue, username, norm);
    }

    void del_user(string username)
    {
        const sql = text("DELETE FROM ", users_table, " WHERE username = ?;");
        query(sql, [username]);

        if (log_user) writeln("Removed user ", blue, username, norm);
    }

    bool user_verify_password(string username, string password)
    {
        const sql = text(
            "SELECT password FROM ", users_table, " WHERE username = ?;"
        );
        const stored_hash = query(sql, [username])[0][0];
        const current_hash = hash_password(password);

        return secureEqual(current_hash, stored_hash);
    }

    void user_update_password(string username, string password)
    {
        const sql = text(
            "UPDATE ", users_table, " SET password = ? WHERE username = ?;"
        );
        const hash = hash_password(password);

        query(sql, [hash, username]);

        if (log_user) writeln(
            "Updated user ", blue, username, norm, "'s password"
        );
    }

    bool user_exists(string username)
    {
        const sql = text(
            "SELECT 1 FROM ", users_table, " WHERE username = ?;"
        );
        return query(sql, [username]).length > 0;
    }

    void add_user_privileges(string username, Duration duration)
    {
        const sql = text(
            "UPDATE ", users_table, " SET privileges = ? WHERE username = ?;"
        );
        auto privileged_until = user_privileged_until(username).toUnixTime;
        const now = Clock.currTime.toUnixTime;

        if (privileged_until < now) privileged_until = now;
        privileged_until += duration.total!"seconds";

        query(sql, [privileged_until.text, username]);

        if (log_user) writeln(
            "Added privileges to user ", blue, username, norm,
        );
    }

    void remove_user_privileges(string username, Duration duration)
    {
        auto privileged_until = user_privileged_until(username).toUnixTime;
        if (privileged_until <= 0)
            return;

        const sql = text(
            "UPDATE ", users_table, " SET privileges = ? WHERE username = ?;"
        );
        const now = Clock.currTime.toUnixTime;
        const seconds = duration.total!"seconds";

        if (privileged_until > now + seconds)
            privileged_until -= seconds;
        else
            privileged_until = now;

        query(sql, [privileged_until.text, username]);

        if (log_user) {
            if (duration == Duration.max)
                writeln(
                    "Removed all privileges from user ", blue, username, norm
                );
            else
                writeln(
                    "Removed some privileges from user ", blue, username, norm
                );
        }
    }

    SysTime user_privileged_until(string username)
    {
        const sql = text(
            "SELECT privileges FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        long privileged_until;

        if (res.length > 0) {
            try {
                privileged_until = res[0][0].to!long;
                if (privileged_until > 0)
                    return SysTime.fromUnixTime(privileged_until);
            }
            catch (ConvException) {}
        }
        return SysTime();
    }

    void ban_user(string username, Duration duration)
    {
        const sql = text(
            "UPDATE ", users_table, " SET banned = ? WHERE username = ?;"
        );
        long banned_until;

        if (duration == Duration.max)
            banned_until = long.max;
        else
            banned_until = (
                Clock.currTime.toUnixTime + duration.total!"seconds");

        query(sql, [banned_until.text, username]);

        if (log_user) writeln("Banned user ", blue, username, norm);
    }

    void unban_user(string username)
    {
        const sql = text(
            "UPDATE ", users_table, " SET banned = ? WHERE username = ?;"
        );
        query(sql, [null, username]);

        if (log_user) writeln("Unbanned user ", blue, username, norm);
    }

    SysTime user_banned_until(string username)
    {
        const sql = text(
            "SELECT banned FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        long banned_until;

        if (res.length > 0) {
            try {
                banned_until = res[0][0].to!long;
                if (banned_until > 0)
                    return SysTime.fromUnixTime(banned_until);
            }
            catch (ConvException) {}
        }
        return SysTime();
    }

    SdbUserStats user_stats(string username)
    {
        const sql = text(
            "SELECT speed,files,folders",
            " FROM ", users_table,
            " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        auto user_stats = SdbUserStats();

        if (res.length > 0) {
            const record                   = res[0];
            user_stats.exists              = true;

            try user_stats.upload_speed    = record[0].to!uint;
            catch (ConvException) {}

            try user_stats.shared_files    = record[1].to!uint;
            catch (ConvException) {}

            try user_stats.shared_folders  = record[2].to!uint;
            catch (ConvException) {}
        }
        return user_stats;
    }

    void user_update_stats(string username, SdbUserStats stats)
    {
        Appender!(string[]) fields;
        Appender!(string[]) parameters;

        if (stats.updating_speed) {
            const upload_speed = stats.upload_speed;
            fields ~= "speed = ?";
            parameters ~= upload_speed > 0 ? upload_speed.text : null;
        }

        if (stats.updating_shared) {
            const shared_files = stats.shared_files;
            fields ~= "files = ?";
            parameters ~= shared_files > 0 ? shared_files.text : null;

            const shared_folders = stats.shared_folders;
            fields ~= "folders = ?";
            parameters ~= shared_folders > 0 ? shared_folders.text : null;
        }

        if (fields[].length == 0)
            return;

        const sql = text(
            "UPDATE ", users_table,
            " SET ", fields[].join(", "),
            " WHERE username = ?;"
        );
        parameters ~= username;
        query(sql, parameters[]);

        if (log_user) writeln(
            "Updated user ", blue, username, norm, "'s stats"
        );
    }

    string[] usernames(string field = null, ulong min = 1,
                       ulong max = ulong.max)
    {
        Appender!(string[]) usernames;
        auto sql = text("SELECT username FROM ", users_table);
        string[] parameters;

        if (field) {
            sql ~= text(" WHERE ", field, " BETWEEN ? AND ?");
            parameters = [min.text, max.text];
        }
        sql ~= ";";
        foreach (ref record ; query(sql, parameters)) usernames ~= record[0];
        return usernames[];
    }

    size_t num_users(string field = null, ulong min = 1, ulong max = ulong.max)
    {
        auto sql = text("SELECT COUNT(1) FROM ", users_table);
        string[] parameters;

        if (field) {
            sql ~= text(" WHERE ", field, " BETWEEN ? AND ?");
            parameters = [min.text, max.text];
        }
        sql ~= ";";
        return query(sql, parameters)[0][0].to!size_t;
    }

    private void raise_sql_error(string query = null,
                                 const string[] parameters = null,
                                 int res = 0)
    {
        const error_code = extended_error_code(db);
        const error_string = error_string(error_code);

        if (query)
            writeln("DB: Query [", query, "]");

        if (parameters)
            writeln("DB: Parameters [", parameters.join(", "), "]");

        if (res)
            writeln("DB: Result code ", res, ".\n\n", error_msg(db), "\n");

        throw new SdbException(
            text("SQLite error ", error_code, " (", error_string, ")")
        );
    }

    private string[][] query(string query, const string[] parameters = null)
    {
        Appender!(string[][]) ret;
        sqlite3_stmt* stmt;

        int res = prepare(db, query, stmt);
        if (res != SQLITE_OK) {
            raise_sql_error(query, parameters, res);
            return ret[];
        }

        foreach (i, ref parameter ; parameters) {
            const index = cast(int) i + 1;
            if (parameter !is null)
                res = bind_text(stmt, index, parameter);
            else
                res = bind_null(stmt, index);

            if (res != SQLITE_OK) {
                finalize(stmt);
                raise_sql_error(query, parameters, res);
                return ret[];
            }
        }

        res = step(stmt);
        while (res == SQLITE_ROW) {
            Appender!(string[]) record;
            foreach (i ; 0 .. column_count(stmt))
                record ~= column_text(stmt, i);

            ret ~= record[];
            res = step(stmt);
        }

        finalize(stmt);

        if (res != SQLITE_DONE)
            raise_sql_error(query, parameters, res);

        return ret[];
    }

    @trusted
    private void initialize()
    {
        if (sqlite3_initialize() != SQLITE_OK)
            raise_sql_error();
    }

    @trusted
    private void shutdown() scope
    {
        if (sqlite3_shutdown() != SQLITE_OK)
            raise_sql_error();
    }

    @trusted
    private void config(int option)
    {
        if (sqlite3_config(option) != SQLITE_OK)
            raise_sql_error();
    }

    @trusted
    private void db_config(sqlite3* db, int option, int value)
    {
        if (sqlite3_db_config(db, option, value, null) != SQLITE_OK)
            // Ignore response, since SQLite versions shipped with older
            // Windows and macOS versions may lack newer options. Other
            // operations will proceed as usual.
            return;
    }

    @trusted
    private void open(string filename)
    {
        if (sqlite3_open(filename.toStringz, &db) != SQLITE_OK)
            raise_sql_error();
    }

    @trusted
    private void close() scope
    {
        if (sqlite3_close(db) != SQLITE_OK)
            raise_sql_error();
    }

    @trusted
    private int extended_error_code(sqlite3* db)
    {
        return sqlite3_extended_errcode(db);
    }

    @trusted
    private string error_msg(sqlite3* db)
    {
        return sqlite3_errmsg(db).fromStringz.idup;
    }

    @trusted
    private string error_string(int error_code)
    {
        return sqlite3_errstr(error_code).fromStringz.idup;
    }

    @trusted
    private int prepare(sqlite3* db, string query, out sqlite3_stmt* statement)
    {
        return sqlite3_prepare_v2(
            db, query.toStringz, cast(int) query.length, &statement, null
        );
    }

    @trusted
    private int bind_null(sqlite3_stmt* statement, int index)
    {
        return sqlite3_bind_null(statement, index);
    }

    @trusted
    private int bind_text(sqlite3_stmt* statement, int index, string value)
    {
        return sqlite3_bind_text(
            statement, index, value.toStringz, cast(int) value.length, null
        );
    }

    @trusted
    private int column_count(sqlite3_stmt* statement)
    {
        return sqlite3_column_count(statement);
    }

    @trusted
    private int step(sqlite3_stmt* statement)
    {
        return sqlite3_step(statement);
    }

    @trusted
    private string column_text(sqlite3_stmt* statement, int index)
    {
        return sqlite3_column_text(statement, index).fromStringz.idup;
    }

    @trusted
    private void finalize(sqlite3_stmt* statement)
    {
        if (sqlite3_finalize(statement) != SQLITE_OK)
            raise_sql_error();
    }
}
