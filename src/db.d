// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import core.time : days, Duration;
import soulfind.defines : blue, default_max_users, default_port, log_db,
                          log_user, norm;
import std.array : Appender;
import std.conv : ConvException, to;
import std.datetime : Clock, SysTime;
import std.digest : digest, LetterCase, secureEqual, toHexString;
import std.digest.md : MD5;
import std.stdio : writefln, writeln;
import std.string : format, fromStringz, join, replace, toStringz;

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

class SdbException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

class Sdb
{
    sqlite3* db;

    const users_table   = "users";
    const admins_table  = "admins";
    const config_table  = "config";


    this(string filename)
    {
        if (log_db) writefln!("DB: Using database: %s")(filename);

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

        const users_sql = format!(
            "CREATE TABLE IF NOT EXISTS %s("
          ~ " username TEXT PRIMARY KEY,"
          ~ " password TEXT,"
          ~ " speed INTEGER,"
          ~ " files INTEGER,"
          ~ " folders INTEGER,"
          ~ " banned INTEGER,"
          ~ " privileges INTEGER"
          ~ ") WITHOUT ROWID;")(
            users_table
        );

        const admins_sql = format!(
            "CREATE TABLE IF NOT EXISTS %s("
          ~ " username TEXT PRIMARY KEY,"
          ~ " level INTEGER"
          ~ ") WITHOUT ROWID;")(
            admins_table
        );

        foreach (problem ; query("PRAGMA integrity_check;"))
            if (log_db) writefln!("DB: Check [%s]")(problem[0]);

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
        const sql = format!(
            "CREATE TABLE IF NOT EXISTS %s("
          ~ " option TEXT PRIMARY KEY,"
          ~ " value"
          ~ ") WITHOUT ROWID;")(
            config_table
        );
        query(sql);

        init_config_option("port", default_port);
        init_config_option("max_users", default_max_users);
        init_config_option("motd", "Soulfind %sversion%");
    }

    private void init_config_option(string option, string value)
    {
        const sql = format!(
            "INSERT OR IGNORE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value]);

        if (log_db) writefln!("DB: Initialized config value %s to %s")(
            option, value
        );
    }

    private void init_config_option(string option, uint value)
    {
        const sql = format!(
            "INSERT OR IGNORE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value.to!string]);

        if (log_db) writefln!("DB: Initialized config value %s to %d")(
            option, value
        );
    }

    void set_config_value(string option, string value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value]);

        if (log_db) writefln!("DB: Updated config value %s to %s")(
            option, value
        );
    }

    void set_config_value(string option, uint value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value.to!string]);

        if (log_db) writefln!("DB: Updated config value %s to %d")(
            option, value
        );
    }

    string get_config_value(string option)
    {
        const sql = format!("SELECT value FROM %s WHERE option = ?;")(
            config_table
        );
        return query(sql, [option])[0][0];
    }

    void add_admin(string username, uint level = 0)
    {
        const sql = format!(
            "REPLACE INTO %s(username, level) VALUES(?, ?);")(
            admins_table
        );
        query(sql, [username, level.to!string]);

        if (log_user) writefln!("Added new admin %s")(blue ~ username ~ norm);
    }

    void del_admin(string username)
    {
        const sql = format!("DELETE FROM %s WHERE username = ?;")(
            admins_table
        );
        query(sql, [username]);

        if (log_user) writefln!("Removed admin %s")(blue ~ username ~ norm);
    }

    string[] admins()
    {
        const sql = format!("SELECT username FROM %s;")(
            admins_table
        );
        Appender!(string[]) admins;
        foreach (record ; query(sql)) admins ~= record[0];
        return admins[];
    }

    bool is_admin(string username)
    {
        const sql = format!(
            "SELECT 1 FROM %s WHERE username = ?;")(
            admins_table
        );
        return query(sql, [username]).length > 0;
    }

    private string hash_password(string password)
    {
        return digest!MD5(password).toHexString!(LetterCase.lower).to!string;
    }

    void add_user(string username, string password)
    {
        const sql = format!(
            "INSERT INTO %s(username, password) VALUES(?, ?);")(
            users_table
        );
        const hash = hash_password(password);

        query(sql, [username, hash]);
        query("PRAGMA optimize;");

        if (log_user) writefln!("Added new user %s")(blue ~ username ~ norm);
    }

    void del_user(string username)
    {
        const sql = format!("DELETE FROM %s WHERE username = ?;")(
            users_table
        );
        query(sql, [username]);

        if (log_user) writefln!("Removed user %s")(blue ~ username ~ norm);
    }

    bool user_verify_password(string username, string password)
    {
        const sql = format!(
            "SELECT password FROM %s WHERE username = ?;")(
            users_table
        );
        const stored_hash = query(sql, [username])[0][0];
        const current_hash = hash_password(password);

        return secureEqual(current_hash, stored_hash);
    }

    void user_update_password(string username, string password)
    {
        const sql = format!(
            "UPDATE %s SET password = ? WHERE username = ?;")(
            users_table
        );
        const hash = hash_password(password);

        query(sql, [hash, username]);

        if (log_user) writefln!("Set user %s's password")(
            blue ~ username ~ norm
        );
    }

    bool user_exists(string username)
    {
        const sql = format!(
            "SELECT 1 FROM %s WHERE username = ?;")(
            users_table
        );
        return query(sql, [username]).length > 0;
    }

    void add_user_privileges(string username, Duration duration)
    {
        const sql = format!(
            "UPDATE %s SET privileges = ? WHERE username = ?;")(
            users_table
        );
        auto privileged_until = user_privileged_until(username).toUnixTime;
        const now = Clock.currTime.toUnixTime;

        if (privileged_until < now) privileged_until = now;
        privileged_until += duration.total!"seconds";

        query(sql, [privileged_until.to!string, username]);

        if (log_user) writefln!(
            "Added %s of privileges to user %s")(
            duration.total!"days".days, blue ~ username ~ norm,
        );
    }

    void remove_user_privileges(string username, Duration duration)
    {
        auto privileged_until = user_privileged_until(username).toUnixTime;
        if (privileged_until <= 0)
            return;

        const sql = format!(
            "UPDATE %s SET privileges = ? WHERE username = ?;")(
            users_table
        );
        const now = Clock.currTime.toUnixTime;
        const seconds = duration.total!"seconds";

        if (privileged_until > now + seconds)
            privileged_until -= seconds;
        else
            privileged_until = now;

        query(sql, [privileged_until.to!string, username]);

        if (log_user) {
            if (duration == Duration.max)
                writefln!(
                    "Removed all privileges from user %s")(
                    blue ~ username ~ norm
                );
            else
                writefln!(
                    "Removed %s of privileges from user %s")(
                    duration.total!"days".days, blue ~ username ~ norm
                );
        }
    }

    bool user_privileged(string username)
    {
        const sql = format!(
            "SELECT 1 FROM %s WHERE username = ? AND privileges > ?;")(
            users_table
        );
        const now = Clock.currTime.toUnixTime;
        return query(sql, [username, now.to!string]).length > 0;
    }

    bool user_supporter(string username)
    {
        const sql = format!(
            "SELECT 1 FROM %s WHERE username = ? AND privileges > ?;")(
            users_table
        );
        const privileged_until = 0;
        return query(sql, [username, privileged_until.to!string]).length > 0;
    }

    SysTime user_privileged_until(string username)
    {
        const sql = format!(
            "SELECT privileges FROM %s WHERE username = ?;")(
            users_table
        );
        const res = query(sql, [username]);
        long privileged_until;

        if (res.length > 0)
            try privileged_until = res[0][0].to!long; catch (ConvException) {}

        return SysTime.fromUnixTime(privileged_until);
    }

    void ban_user(string username, Duration duration)
    {
        const sql = format!(
            "UPDATE %s SET banned = ? WHERE username = ?;")(
            users_table
        );
        long banned_until;

        if (duration == Duration.max)
            banned_until = long.max;
        else
            banned_until = (
                Clock.currTime.toUnixTime + duration.total!"seconds");

        query(sql, [banned_until.to!string, username]);

        if (log_user) writefln!("Banned user %s")(blue ~ username ~ norm);
    }

    void unban_user(string username)
    {
        const sql = format!(
            "UPDATE %s SET banned = ? WHERE username = ?;")(
            users_table
        );
        const banned_until = 0;
        query(sql, [banned_until.to!string, username]);

        if (log_user) writefln!("Unbanned user %s")(blue ~ username ~ norm);
    }

    bool user_banned(string username)
    {
        const sql = format!(
            "SELECT 1 FROM %s WHERE username = ? AND banned > ?;")(
            users_table
        );
        const now = Clock.currTime.toUnixTime;
        return query(sql, [username, now.to!string]).length > 0;
    }

    SysTime user_banned_until(string username)
    {
        const sql = format!(
            "SELECT banned FROM %s WHERE username = ?;")(
            users_table
        );
        const res = query(sql, [username]);
        long banned_until;

        if (res.length > 0)
            try banned_until = res[0][0].to!long; catch (ConvException) {}

        return SysTime.fromUnixTime(banned_until);
    }

    SdbUserStats user_stats(string username)
    {
        const sql = format!(
            "SELECT speed,files,folders"
          ~ " FROM %s"
          ~ " WHERE username = ?;")(
            users_table
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
        string[] fields;
        string[] parameters;

        if (stats.updating_speed) {
            fields ~= "speed = ?";
            parameters ~= stats.upload_speed.to!string;
        }

        if (stats.updating_shared) {
            fields ~= "files = ?";
            parameters ~= stats.shared_files.to!string;

            fields ~= "folders = ?";
            parameters ~= stats.shared_folders.to!string;
        }

        if (!fields)
            return;

        const sql = format!(
            "UPDATE %s SET %s WHERE username = ?;")(
            users_table, fields.join(", ")
        );

        if (log_user) {
            string updated;
            foreach (i, field; fields)
            {
                if (i > 0) updated ~= ", ";
                updated ~= field.replace("?", parameters[i]);
            }
            writefln!(
                "Updating user %s's stats (%s)")(
                blue ~ username ~ norm, updated
            );
        }

        parameters ~= stats.username;
        query(sql, parameters);
    }

    string[] usernames(string field = null, ulong min = 1,
                       ulong max = ulong.max)
    {
        Appender!(string[]) usernames;
        auto sql = format!("SELECT username FROM %s")(users_table);
        string[] parameters;

        if (field) {
            sql ~= format!(" WHERE %s BETWEEN ? AND ?")(field);
            parameters = [min.to!string, max.to!string];
        }
        sql ~= ";";
        foreach (record ; query(sql, parameters)) usernames ~= record[0];
        return usernames[];
    }

    uint num_users(string field = null, ulong min = 1, ulong max = ulong.max)
    {
        auto sql = format!("SELECT COUNT(1) FROM %s")(users_table);
        string[] parameters;

        if (field) {
            sql ~= format!(" WHERE %s BETWEEN ? AND ?")(field);
            parameters = [min.to!string, max.to!string];
        }
        sql ~= ";";
        return query(sql, parameters)[0][0].to!uint;
    }

    private void raise_sql_error(string query = null,
                                 const string[] parameters = null,
                                 int res = 0)
    {
        const error_code = extended_error_code(db);
        const error_string = error_string(error_code);

        if (query)
            writefln!("DB: Query [%s]")(query);

        if (parameters)
            writefln!("DB: Parameters [%s]")(parameters.join(", "));

        if (res)
            writefln!("DB: Result code %d.\n\n%s\n")(res, error_msg(db));

        throw new SdbException(
            format!("SQLite error %d (%s)")(error_code, error_string)
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

        foreach (i, parameter ; parameters) {
            res = bind_text(stmt, cast(int) i + 1, parameter);
            if (res != SQLITE_OK) {
                finalize(stmt);
                raise_sql_error(query, parameters, res);
                return ret[];
            }
        }

        res = step(stmt);
        while (res == SQLITE_ROW) {
            string[] record;
            foreach (i ; 0 .. column_count(stmt))
                record ~= column_text(stmt, i);

            ret ~= record;
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
