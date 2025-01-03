// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import etc.c.sqlite3 : sqlite3, sqlite3_close, sqlite3_column_count,
                       sqlite3_column_text, sqlite3_errstr, sqlite3_finalize,
                       sqlite3_open, sqlite3_prepare_v2, sqlite3_step,
                       sqlite3_stmt, SQLITE_DONE, SQLITE_OK, SQLITE_ROW;
import soulfind.defines : blue, default_max_users, default_port, norm;
import std.conv : to;
import std.exception : ifThrown;
import std.file : exists, isFile;
import std.stdio : writefln, writeln;
import std.string : format, replace, toStringz;

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
    sqlite3*       db;
    sqlite3_stmt*  stmt;

    const users_table   = "users";
    const admins_table  = "admins";
    const config_table  = "config";


    this(string filename)
    {
        debug(db) writefln!("DB: Using database: %s")(filename);
        open_db(filename);

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

        query(users_sql);
        query(admins_sql);
        init_config();
    }

    ~this()
    {
        debug(db) writeln("DB: Shutting down...");
        close_db();
    }

    @trusted
    private void open_db(string filename)
    {
        sqlite3_open(filename.toStringz(), &db);
    }

    @trusted
    private void close_db()
    {
        sqlite3_close(db);
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
            "INSERT OR IGNORE INTO %s(option, value) VALUES('%s', '%s');")(
            config_table, option, escape(value)
        );
        query(sql);
    }

    private void init_config_option(string option, uint value)
    {
        const sql = format!(
            "INSERT OR IGNORE INTO %s(option, value) VALUES('%s', %d);")(
            config_table, option, value
        );
        query(sql);
    }

    void set_config_value(string option, string value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES('%s', '%s');")(
            config_table, option, escape(value)
        );
        query(sql);
    }

    void set_config_value(string option, uint value)
    {
        const sql = format!(
            "REPLACE INTO %s(option, value) VALUES('%s', %d);")(
            config_table, option, value
        );
        query(sql);
    }

    string get_config_value(string option)
    {
        const sql = format!("SELECT value FROM %s WHERE option = '%s';")(
            config_table, option
        );
        return query(sql)[0][0];
    }

    void add_admin(string username, uint level = 0)
    {
        const sql = format!(
            "REPLACE INTO %s(username, level) VALUES('%s', %d);")(
            admins_table, escape(username), level
        );
        query(sql);
    }

    void del_admin(string username)
    {
        const sql = format!("DELETE FROM %s WHERE username = '%s';")(
            admins_table, escape(username)
        );
        query(sql);
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
            "SELECT username FROM %s WHERE username = '%s';")(
            admins_table, escape(username)
        );
        return query(sql).length > 0;
    }

    void add_user(string username, string password)
    {
        const sql = format!(
            "INSERT INTO %s(username, password) VALUES('%s', '%s');")(
            users_table, escape(username), escape(password)
        );
        query(sql);
    }

    bool user_exists(string username)
    {
        const sql = format!(
            "SELECT username FROM %s WHERE username = '%s';")(
            users_table, escape(username)
        );
        return query(sql).length > 0;
    }

    void user_update_field(string username, string field, string value)
    {
        const sql = format!(
            "UPDATE %s SET %s = '%s' WHERE username = '%s';")(
            users_table, field, escape(value), escape(username)
        );
        query(sql);
    }

    void user_update_field(string username, string field, ulong value)
    {
        const sql = format!(
            "UPDATE %s SET %s = %d WHERE username = '%s';")(
            users_table, field, value, escape(username)
        );
        query(sql);
    }

    string get_pass(string username)
    {
        const sql = format!(
            "SELECT password FROM %s WHERE username = '%s';")(
            users_table, escape(username)
        );
        return query(sql)[0][0];
    }

    long get_user_privileges(string username)
    {
        const sql = format!(
            "SELECT privileges FROM %s WHERE username = '%s';")(
            users_table, escape(username)
        );
        return query(sql)[0][0].to!long.ifThrown(0);
    }

    bool is_banned(string username)
    {
        const sql = format!(
            "SELECT banned FROM %s WHERE username = '%s';")(
            users_table, escape(username)
        );
        const res = query(sql);

        if (res.length > 0)
            return res[0][0].to!uint.ifThrown(0) > 0;

        return false;
    }

    SdbUserStats get_user_stats(string username)
    {
        debug(db) writefln!("DB: Requested %s's info...")(
            blue ~ username ~ norm
        );
        const sql = format!(
            "SELECT speed,ulnum,files,folders"
          ~ " FROM %s"
          ~ " WHERE username = '%s';")(
            users_table, escape(username)
        );
        const res = query(sql);
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

    string[] usernames(string filter_field = null, uint min = 1, uint max = -1)
    {
        string[] ret;
        auto sql = format!("SELECT username FROM %s")(users_table);
        if (filter_field) sql ~= format!(" WHERE %s BETWEEN %d AND %d")(
            escape(filter_field), min, max
        );
        sql ~= ";";
        foreach (record ; query(sql)) ret ~= record[0];
        return ret;
    }

    uint num_users(string filter_field = null, uint min = 1, uint max = -1)
    {
        auto sql = format!("SELECT COUNT(1) FROM %s")(users_table);
        if (filter_field) sql ~= format!(" WHERE %s BETWEEN %d AND %d")(
            escape(filter_field), min, max
        );
        sql ~= ";";
        return query(sql)[0][0].to!uint.ifThrown(0);
    }

    @trusted
    private string[][] query(string query)
    {
        string[][] ret;
        char* tail;
        uint res;
        uint fin;

        debug(db) writefln!("DB: Query [%s]")(query);
        sqlite3_prepare_v2(
            db, query.toStringz(), cast(uint)query.length, &stmt, &tail);

        res = sqlite3_step(stmt);

        while (res == SQLITE_ROW) {
            string[] record;
            const n = sqlite3_column_count(stmt);

            for (uint i ; i < n ; i++)
                record ~= sqlite3_column_text(stmt, i).to!string;

            ret ~= record;
            res = sqlite3_step(stmt);
        }

        fin = sqlite3_finalize(stmt);

        if (res != SQLITE_DONE || fin != SQLITE_OK) {
            // https://sqlite.org/rescode.html#extrc
            debug(db) writefln!("DB: Result Code %d (%s)")(
                res, sqlite3_errstr(res).to!string
            );
            debug(db) writefln!("    >Final Code %d (%s)")(
                fin, sqlite3_errstr(fin).to!string
            );
            throw new Exception(sqlite3_errstr(fin).to!string);
        }
        return ret;
    }

    private string escape(string str)
    {
        return replace(str, "'", "''");
    }
}
