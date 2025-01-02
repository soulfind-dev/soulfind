// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import etc.c.sqlite3 : sqlite3, sqlite3_close, sqlite3_column_count,
                       sqlite3_column_text, sqlite3_errstr, sqlite3_finalize,
                       sqlite3_open, sqlite3_prepare_v2, sqlite3_step,
                       sqlite3_stmt, SQLITE_DONE, SQLITE_OK, SQLITE_ROW;
import soulfind.defines : default_max_users, default_port;
import std.conv : to;
import std.exception : ifThrown;
import std.file : exists, isFile;
import std.stdio : writefln;
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
        open_db(filename);

        if (!exists(filename) || !isFile(filename))
            throw new Exception(
                "Cannot create database file %s".format(filename));

        query(
            "CREATE TABLE IF NOT EXISTS %s(
                username TEXT PRIMARY KEY,
                password TEXT,
                speed INTEGER,
                ulnum INTEGER,
                files INTEGER,
                folders INTEGER,
                banned INTEGER,
                privileges INTEGER
            ) WITHOUT ROWID;".format(users_table)
        );
        query(
            "CREATE TABLE IF NOT EXISTS %s(
                username TEXT PRIMARY KEY,
                level INTEGER
            ) WITHOUT ROWID;".format(admins_table)
        );
        init_config();
    }

    @trusted
    private void open_db(string filename)
    {
        sqlite3_open(filename.toStringz(), &db);
    }

    private void init_config()
    {
        query(
            "CREATE TABLE IF NOT EXISTS %s(
                option TEXT PRIMARY KEY,
                value
            ) WITHOUT ROWID;".format(config_table)
        );

        init_config_option("port", default_port);
        init_config_option("max_users", default_max_users);
        init_config_option("motd", "Soulfind %sversion%");
    }

    private void init_config_option(string option, string value)
    {
        query(
            "INSERT OR IGNORE INTO %s(option, value)
             VALUES('%s', '%s');".format(
            config_table, option, escape(value)
        ));
    }

    private void init_config_option(string option, uint value)
    {
        query(
            "INSERT OR IGNORE INTO %s(option, value) VALUES('%s', %d);".format(
            config_table, option, value
        ));
    }

    void set_config_value(string option, string value)
    {
        query(
            "REPLACE INTO %s(option, value) VALUES('%s', '%s');".format(
            config_table, option, escape(value)
        ));
    }

    void set_config_value(string option, uint value)
    {
        query(
            "REPLACE INTO %s(option, value) VALUES('%s', %d);".format(
            config_table, option, value
        ));
    }

    string get_config_value(string option)
    {
        return query(
            "SELECT value FROM %s WHERE option = '%s';".format(
            config_table, option)
        )[0][0];
    }

    void add_admin(string username, uint level = 0)
    {
        query(
            "REPLACE INTO %s(username, level) VALUES('%s', %d);".format(
            admins_table, escape(username), level
        ));
    }

    void del_admin(string username)
    {
        query(
            "DELETE FROM %s WHERE username = '%s';".format(
            admins_table, escape(username)
        ));
    }

    string[] admins()
    {
        string[] ret;
        foreach (record ; query("SELECT username FROM %s;".format(
                 admins_table)))
            ret ~= record[0];
        return ret;
    }

    bool is_admin(string username)
    {
        return query(
            "SELECT username FROM %s WHERE username = '%s';".format(
            admins_table, escape(username)
        )).length > 0;
    }

    void add_user(string username, string password)
    {
        query(
            "INSERT INTO %s(username, password) VALUES('%s', '%s');".format(
            users_table, escape(username), escape(password)
        ));
    }

    bool user_exists(string username)
    {
        return query(
            "SELECT username FROM %s WHERE username = '%s';".format(
            users_table, escape(username)
        )).length > 0;
    }

    void user_update_field(string username, string field, string value)
    {
        query(
            "UPDATE %s SET %s = '%s' WHERE username = '%s';".format(
            users_table, field, escape(value), escape(username)
        ));
    }

    void user_update_field(string username, string field, ulong value)
    {
        query(
            "UPDATE %s SET %s = %d WHERE username = '%s';".format(
            users_table, field, value, escape(username)
        ));
    }

    string get_pass(string username)
    {
        return query(
            "SELECT password FROM %s WHERE username = '%s';".format(
            users_table, escape(username)
        ))[0][0];
    }

    long get_user_privileges(string username)
    {
        return query(
            "SELECT privileges FROM %s WHERE username = '%s';".format(
            users_table, escape(username)
        ))[0][0].to!long.ifThrown(0);
    }

    bool is_banned(string username)
    {
        const res = query(
            "SELECT banned FROM %s WHERE username = '%s';".format(
            users_table, escape(username)
        ));

        if (res.length > 0)
            return res[0][0].to!uint.ifThrown(0) > 0;

        return false;
    }

    SdbUserStats get_user_stats(string username)
    {
        debug(db) writefln(
            "DB: Requested %s's info...", blue ~ username ~ norm);
        const res = query(
            "SELECT speed,ulnum,files,folders
             FROM %s
             WHERE username = '%s';".format(
            users_table, escape(username)
        ));
        auto user_stats = SdbUserStats();

        if (res.length > 0) {
            const user                 = res[0];
            user_stats.exists          = true;
            user_stats.speed           = user[0].to!uint.ifThrown(0);
            user_stats.upload_number   = user[1].to!uint.ifThrown(0);
            user_stats.shared_files    = user[2].to!uint.ifThrown(0);
            user_stats.shared_folders  = user[3].to!uint.ifThrown(0);
        }
        return user_stats;
    }

    string[] usernames(string filter_field = null, uint min = 1, uint max = -1)
    {
        string[] ret;
        string query_str = "SELECT username FROM %s".format(users_table);
        if (filter_field) query_str ~= " WHERE %s BETWEEN %d AND %d".format(
            escape(filter_field), min, max
        );
        query_str ~= ";";
        foreach (record ; query(query_str)) ret ~= record[0];
        return ret;
    }

    uint num_users(string filter_field = null, uint min = 1, uint max = -1)
    {
        string query_str = "SELECT COUNT(1) FROM %s".format(users_table);
        if (filter_field) query_str ~= " WHERE %s BETWEEN %d AND %d".format(
            escape(filter_field), min, max
        );
        query_str ~= ";";
        return query(query_str)[0][0].to!uint.ifThrown(0);
    }

    @trusted
    private string[][] query(string query)
    {
        string[][] ret;
        char* tail;
        uint res;
        uint fin;

        debug(db) writefln("DB: Query [%s]", query);
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
            debug(db) writefln(
                "DB: Result Code %d (%s)", res, sqlite3_errstr(res).to!string);
            debug(db) writefln(
                "    >Final Code %d (%s)", fin, sqlite3_errstr(fin).to!string);
            throw new Exception(sqlite3_errstr(fin).to!string);
        }
        return ret;
    }

    private string escape(string str)
    {
        return replace(str, "'", "''");
    }
}
