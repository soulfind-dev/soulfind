// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import etc.c.sqlite3 : sqlite3, sqlite3_bind_text, sqlite3_close,
                       sqlite3_column_count, sqlite3_column_text,
                       sqlite3_errmsg, sqlite3_errstr,
                       sqlite3_extended_errcode, sqlite3_finalize,
                       sqlite3_open, sqlite3_prepare_v2, sqlite3_step,
                       sqlite3_stmt, SQLITE_DONE, SQLITE_OK, SQLITE_ROW,
                       SQLITE_TRANSIENT;
import soulfind.defines : blue, default_max_users, default_port, norm;
import std.conv : to;
import std.exception : ifThrown;
import std.file : exists, isFile;
import std.stdio : writefln, writeln;
import std.string : format, fromStringz, join, replace, toStringz;

struct SdbUserStats
{
    string  username;
    bool    exists;
    uint    speed;
    uint    upload_number;
    uint    shared_files;
    uint    shared_folders;
}

class Sdb
{
    sqlite3* db;

    const users_table   = "users";
    const admins_table  = "admins";
    const config_table  = "config";


    this(string filename)
    {
        debug(db) writefln!("DB: Using database: %s")(filename);
        open(filename);

        if (!exists(filename) || !isFile(filename))
            throw new Exception(
                format!("Cannot create database file %s")(filename));

        const users_sql = format!(
            "CREATE TABLE IF NOT EXISTS %s("
          ~ " username TEXT PRIMARY KEY,"
          ~ " password TEXT,"
          ~ " speed INTEGER,"
          ~ " ulnum INTEGER,"
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
            debug(db) writefln!("DB: Check [%s]")(problem[0]);

        query("PRAGMA optimize=0x10002;");  // =all tables
        query(users_sql);
        query(admins_sql);
        init_config();
    }

    ~this()
    {
        debug(db) writeln("DB: Shutting down...");
        close();
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
    }

    private void init_config_option(string option, uint value)
    {
        const sql = format!(
            "INSERT OR IGNORE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value.to!string]);
    }

    void set_config_value(string option, string value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value]);
    }

    void set_config_value(string option, uint value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES(?, ?);")(
            config_table
        );
        query(sql, [option, value.to!string]);
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
    }

    void del_admin(string username)
    {
        const sql = format!("DELETE FROM %s WHERE username = ?;")(
            admins_table
        );
        query(sql, [username]);
    }

    string[] admins()
    {
        const sql = format!("SELECT username FROM %s;")(
            admins_table
        );
        string[] admins;
        foreach (record ; query(sql)) admins ~= record[0];
        return admins;
    }

    bool is_admin(string username)
    {
        const sql = format!(
            "SELECT username FROM %s WHERE username = ?;")(
            admins_table
        );
        return query(sql, [username]).length > 0;
    }

    void add_user(string username, string password)
    {
        const sql = format!(
            "INSERT INTO %s(username, password) VALUES(?, ?);")(
            users_table
        );
        query(sql, [username, password]);
        query("PRAGMA optimize;");
    }

    bool user_exists(string username)
    {
        const sql = format!(
            "SELECT username FROM %s WHERE username = ?;")(
            users_table
        );
        return query(sql, [username]).length > 0;
    }

    void user_update_field(string username, string field, string value)
    {
        const sql = format!(
            "UPDATE %s SET %s = ? WHERE username = ?;")(
            users_table, field
        );
        query(sql, [value, username]);
    }

    void user_update_field(string username, string field, ulong value)
    {
        const sql = format!(
            "UPDATE %s SET %s = ? WHERE username = ?;")(
            users_table, field
        );
        query(sql, [value.to!string, username]);
    }

    string get_pass(string username)
    {
        const sql = format!(
            "SELECT password FROM %s WHERE username = ?;")(
            users_table
        );
        return query(sql, [username])[0][0];
    }

    long get_user_privileges(string username)
    {
        const sql = format!(
            "SELECT privileges FROM %s WHERE username = ?;")(
            users_table
        );
        return query(sql, [username])[0][0].to!long.ifThrown(0);
    }

    long get_ban_expiration(string username)
    {
        const sql = format!(
            "SELECT banned FROM %s WHERE username = ?;")(
            users_table
        );
        return query(sql, [username])[0][0].to!long.ifThrown(0);
    }

    SdbUserStats get_user_stats(string username)
    {
        debug(db) writefln!("DB: Requested %s's info...")(
            blue ~ username ~ norm
        );
        const sql = format!(
            "SELECT speed,ulnum,files,folders"
          ~ " FROM %s"
          ~ " WHERE username = ?;")(
            users_table
        );
        const res = query(sql, [username]);
        auto user_stats = SdbUserStats();

        if (res.length > 0) {
            const record               = res[0];
            user_stats.exists          = true;
            user_stats.speed           = record[0].to!uint.ifThrown(0);
            user_stats.upload_number   = record[1].to!uint.ifThrown(0);
            user_stats.shared_files    = record[2].to!uint.ifThrown(0);
            user_stats.shared_folders  = record[3].to!uint.ifThrown(0);
        }
        return user_stats;
    }

    string[] usernames(string field = null, ulong min = 1,
                       ulong max = ulong.max)
    {
        string[] ret;
        auto sql = format!("SELECT username FROM %s")(users_table);
        string[] parameters;

        if (field) {
            sql ~= format!(" WHERE %s BETWEEN ? AND ?")(field);
            parameters = [min.to!string, max.to!string];
        }
        sql ~= ";";
        foreach (record ; query(sql, parameters)) ret ~= record[0];
        return ret;
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
        return query(sql, parameters)[0][0].to!uint.ifThrown(0);
    }

    private void raise_sql_error(string query, const string[] parameters,
                                 int res)
    {
        const error_code = extended_error_code(db);
        const error_string = error_string(error_code);

        writefln!("DB: Query [%s]")(query);
        writefln!("DB: Parameters [%s]")(parameters.join(", "));
        writefln!("DB: Result code %d.\n\n%s\n")(res, error_msg(db));

        throw new Exception(
            format!("SQLite error %d (%s)")(error_code, error_string)
        );
    }

    private string[][] query(string query, const string[] parameters = [])
    {
        string[][] ret;
        sqlite3_stmt* stmt;

        int res = prepare(db, query, stmt);
        if (res != SQLITE_OK) {
            raise_sql_error(query, parameters, res);
            return ret;
        }

        foreach (i, parameter ; parameters) {
            res = bind_text(stmt, cast(int) i + 1, parameter);
            if (res != SQLITE_OK) {
                finalize(stmt);
                raise_sql_error(query, parameters, res);
                return ret;
            }
        }

        res = step(stmt);

        while (res == SQLITE_ROW) {
            string[] record;
            const n = column_count(stmt);

            for (int i ; i < n ; i++)
                record ~= column_text(stmt, i);

            ret ~= record;
            res = step(stmt);
        }

        finalize(stmt);

        if (res != SQLITE_DONE)
            raise_sql_error(query, parameters, res);

        return ret;
    }

    @trusted
    private void open(string filename)
    {
        sqlite3_open(filename.toStringz, &db);
    }

    @trusted
    private void close() scope
    {
        sqlite3_close(db);
    }

    @trusted
    private int extended_error_code(sqlite3* db)
    {
        return sqlite3_extended_errcode(db);
    }

    @trusted
    private string error_string(int error_code)
    {
        return sqlite3_errstr(error_code).fromStringz.idup;
    }

    @trusted
    private string error_msg(sqlite3* db)
    {
        return sqlite3_errmsg(db).fromStringz.idup;
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
            statement, index, value.toStringz, cast(int) value.length,
            SQLITE_TRANSIENT
        );
    }

    @trusted
    private void finalize(sqlite3_stmt* statement)
    {
        sqlite3_finalize(statement);
    }

    @trusted
    private int step(sqlite3_stmt* statement)
    {
        return sqlite3_step(statement);
    }

    @trusted
    private int column_count(sqlite3_stmt* statement)
    {
        return sqlite3_column_count(statement);
    }

    @trusted
    private string column_text(sqlite3_stmt* statement, int index)
    {
        return sqlite3_column_text(statement, index).fromStringz.idup;
    }
}
