// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

debug(db) import core.time : MonoTime, usecs;  // only used for query() timing
import etc.c.sqlite3 : sqlite3, sqlite3_close, sqlite3_column_count,
                       sqlite3_column_text, sqlite3_errmsg, sqlite3_errstr,
                       sqlite3_extended_errcode, sqlite3_finalize,
                       sqlite3_initialize, sqlite3_memory_highwater,
                       sqlite3_open, sqlite3_prepare_v2, sqlite3_shutdown,
                       sqlite3_step, sqlite3_stmt, sqlite3_total_changes,
                       SQLITE_OK, SQLITE_ROW;
import soulfind.defines : blue, default_max_users, default_port, norm;
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
    sqlite3* db;

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

        foreach (problem ; query("PRAGMA integrity_check;"))
            debug(db) writefln!("DB: Check [%s]")(problem[0]);

        query("PRAGMA reverse_unordered_selects=1;");  // Prefer recent users
        query("PRAGMA optimize=0x10002;");  // =all tables
        query(users_sql);
        query(admins_sql);
        init_config();
    }

    ~this()
    {
        close_db();
    }

    @trusted
    private void open_db(string filename)
    {
        // https://www.sqlite.org/c3ref/initialize.html
        // "Future releases of SQLite may require this"
        if (sqlite3_initialize() != SQLITE_OK)
            throw new Exception("Cannot start SQLite");

        sqlite3_open(filename.toStringz(), &db);

        // https://www.sqlite.org/c3ref/c_dbconfig_defensive.html
        with (imported!"etc.c.sqlite3 : sqlite3_db_config,
                        SQLITE_DBCONFIG_DEFENSIVE,
                        SQLITE_DBCONFIG_ENABLE_TRIGGER,
                        SQLITE_DBCONFIG_ENABLE_VIEW,
                        SQLITE_DBCONFIG_TRUSTED_SCHEMA")
        {
            sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, null);
            sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, null);
            sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, null);
            sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, null);
            //sqlite3_db_config(db, SQLITE_DBCONFIG_REVERSE_SCANORDER, 1, null);
        }

        // https://www.sqlite.org/c3ref/c_limit_attached.html
        with (imported!"etc.c.sqlite3 : sqlite3_limit,
                        SQLITE_LIMIT_LENGTH, SQLITE_LIMIT_SQL_LENGTH,
                        SQLITE_LIMIT_COLUMN, SQLITE_LIMIT_EXPR_DEPTH,
                        SQLITE_LIMIT_COMPOUND_SELECT, SQLITE_LIMIT_VDBE_OP,
                        SQLITE_LIMIT_FUNCTION_ARG, SQLITE_LIMIT_ATTACHED,
                        SQLITE_LIMIT_LIKE_PATTERN_LENGTH,
                        SQLITE_LIMIT_VARIABLE_NUMBER,
                        SQLITE_LIMIT_TRIGGER_DEPTH")
        {
            sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 32768);              // 0
            sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 512);            // 1
            sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 8);                  // 2
            sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 10);             // 3
            sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 2);         // 4
            sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);             // 5
            sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 10);           // 6
            sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0);                // 7
            sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 30);    // 8
            sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 9);         // 9
            sqlite3_limit(db, SQLITE_LIMIT_TRIGGER_DEPTH, 1);           // 10
        }
    }

    @trusted
    private void close_db() scope
    {
        debug(db) {
            writefln!(
                "DB: Shutting down...\n"
              ~ "DB: %d Bytes memory was in use\n"
              ~ "DB: %d total changes\n"
              ~ "DB: SQLITE Error %d")(
                sqlite3_memory_highwater(1),
                sqlite3_total_changes(db),
                sqlite3_extended_errcode(db)
            );
        }
        sqlite3_close(db);
        sqlite3_shutdown();  // deallocates resources in Termux
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
        query("PRAGMA secure_delete=1;");
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
        query("PRAGMA optimize;");
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

    string[] usernames(string field = null, ulong min = 1, ulong max = -1)
    {
        string[] ret;
        auto sql = format!("SELECT username FROM %s")(users_table);
        if (field) sql ~= format!(" WHERE %s BETWEEN %d AND %d")(
            escape(field), min, max
        );
        sql ~= ";";
        foreach (record ; query(sql)) ret ~= record[0];
        return ret;
    }

    uint num_users(string field = null, ulong min = 1, ulong max = -1)
    {
        auto sql = format!("SELECT COUNT(1) FROM %s")(users_table);
        if (field) sql ~= format!(" WHERE %s BETWEEN %d AND %d")(
            escape(field), min, max
        );
        sql ~= ";";
        return query(sql)[0][0].to!uint.ifThrown(0);
    }

    @trusted
    private string[][] query(string query)
    {
        string[][] ret;
        sqlite3_stmt* stmt;
        char* tail;

        sqlite3_prepare_v2(
            db, query.toStringz(), cast(uint)query.length, &stmt, &tail);

        uint res = sqlite3_step(stmt);

        while (res == SQLITE_ROW) {
            string[] record;
            const n = sqlite3_column_count(stmt);

            for (uint i ; i < n ; i++)
                record ~= sqlite3_column_text(stmt, i).to!string;

            ret ~= record;
            res = sqlite3_step(stmt);
        }

        uint fin = sqlite3_finalize(stmt);
        uint err = sqlite3_extended_errcode(db);

        if (err) {
            writefln!(
                "DB: Query [%s]\nDB: Result Code %d, Final Code %d.\n\n%s\n")(
                query, res, fin, sqlite3_errmsg(db).to!string
            );
            throw new Exception(
                format!("Error %d (%s)")(err, sqlite3_errstr(err).to!string)
            );
        }
        return ret;
    }

    private string escape(string str)
    {
        return replace(str, "'", "''");
    }
}
