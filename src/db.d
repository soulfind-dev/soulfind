// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.db;
@safe:

import soulfind.defines : blue, default_max_users, default_motd, default_port,
                          default_private_mode, log_db, log_user, norm,
                          RoomMemberType, RoomType, SearchFilterType;
import std.array : Appender;
import std.conv : ConvException, text, to;
import std.datetime : Clock, days, Duration, SysTime, UTC;
import std.file : exists, remove, rename;
import std.path : absolutePath, buildNormalizedPath;
import std.stdio : writeln;
import std.string : fromStringz, join, replace, toStringz;

extern (C) {
    // Manual definitions due to etc.c.sqlite3 bindings being out of date, or
    // missing in certain GDC versions.
    // https://github.com/dlang/phobos/blob/HEAD/etc/c/sqlite3.d

    immutable(char)* sqlite3_libversion();

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

enum users_table           = "users";
enum config_table          = "config";
enum rooms_table           = "rooms";
enum room_members_table    = "room_members";
enum tickers_table         = "tickers";
enum search_filters_table  = "search_filters";
enum search_query_table    = "temp.search_query";

struct SdbUserStats
{
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
    private sqlite3* db;
    private string db_filename;


    this(string filename)
    {
        this.db_filename = filename.absolutePath.buildNormalizedPath;
        if (log_db) writeln("DB: Using database: ", db_filename);

        // Soulfind is single-threaded. Disable SQLite mutexes for a slight
        // performance improvement.
        config(SQLITE_CONFIG_SINGLETHREAD);

        initialize();
        open(db_filename);

        // https://www.sqlite.org/security.html
        db_config(SQLITE_DBCONFIG_DEFENSIVE, 1);
        db_config(SQLITE_DBCONFIG_ENABLE_TRIGGER, 0);
        db_config(SQLITE_DBCONFIG_ENABLE_VIEW, 0);
        db_config(SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0);

        query("PRAGMA journal_mode = WAL;");
        query("PRAGMA synchronous = NORMAL;");
        query("PRAGMA foreign_keys = ON;");
        query("PRAGMA secure_delete = ON;");

        enum users_table_sql = text(
            "CREATE TABLE IF NOT EXISTS ", users_table,
            "(username TEXT PRIMARY KEY,",
            " password TEXT NOT NULL,",
            " speed INTEGER,",
            " files INTEGER,",
            " folders INTEGER,",
            " banned INTEGER,",
            " privileges INTEGER,",
            " admin INTEGER",
            " unsearchable INTEGER",
            ") WITHOUT ROWID;"
        );

        enum rooms_table_sql = text(
            "CREATE TABLE IF NOT EXISTS ", rooms_table,
            "(room TEXT PRIMARY KEY,",
            " type INTEGER NOT NULL,",
            " owner TEXT,",
            " FOREIGN KEY(owner) REFERENCES ", users_table, "(username) ",
            "ON UPDATE CASCADE ON DELETE CASCADE",
            ") WITHOUT ROWID;"
        );

        enum room_members_sql = text(
            "CREATE TABLE IF NOT EXISTS ", room_members_table,
            "(room TEXT,",
            " username TEXT,",
            " type INTEGER NOT NULL,",
            " PRIMARY KEY(room, username),",
            " FOREIGN KEY(room) REFERENCES ", rooms_table, "(room) ",
            "ON UPDATE CASCADE ON DELETE CASCADE,",
            " FOREIGN KEY(username) REFERENCES ", users_table, "(username) ",
            "ON UPDATE CASCADE ON DELETE CASCADE",
            ") WITHOUT ROWID;"
        );

        enum tickers_table_sql = text(
            "CREATE TABLE IF NOT EXISTS ", tickers_table,
            "(room TEXT,",
            " username TEXT,",
            " content TEXT NOT NULL,",
            " PRIMARY KEY(room, username),",
            " FOREIGN KEY(room) REFERENCES ", rooms_table, "(room) ",
            "ON UPDATE CASCADE ON DELETE CASCADE,",
            " FOREIGN KEY(username) REFERENCES ", users_table, "(username) ",
            "ON UPDATE CASCADE ON DELETE CASCADE",
            ");"
        );

        enum search_filters_table_sql = text(
            "CREATE TABLE IF NOT EXISTS ", search_filters_table,
            "(type INTEGER,",
            " phrase TEXT,",
            " PRIMARY KEY (type, phrase)",
            ") WITHOUT ROWID;"
        );

        enum search_query_table_sql = text(
            "CREATE VIRTUAL TABLE ", search_query_table,
            " USING fts5(query);"
        );

        enum rooms_type_index_sql = text(
            "CREATE INDEX IF NOT EXISTS ", rooms_table, "_type_index ",
            " ON ", rooms_table, "(type);"
        );

        enum rooms_owner_type_index_sql = text(
            "CREATE INDEX IF NOT EXISTS ", rooms_table, "_owner_type_index ",
            " ON ", rooms_table, "(owner, type);"
        );

        foreach (ref problem ; query("PRAGMA integrity_check;"))
            if (log_db) writeln("DB: Check [", problem[0], "]");

        query("PRAGMA optimize=0x10002;");  // =all tables
        query(users_table_sql);
        query(rooms_table_sql);
        query(room_members_sql);
        query(tickers_table_sql);
        query(search_filters_table_sql);
        query(search_query_table_sql);
        query(rooms_type_index_sql);
        query(rooms_owner_type_index_sql);
        add_new_columns();
        init_config();
    }

    ~this()
    {
        if (log_db) writeln("DB: Shutting down...");
        close();
        shutdown();
    }


    // Migration

    private void add_new_columns()
    {
        // Temporary migration code to add new columns
        enum sql = text("PRAGMA table_info(", users_table, ");");
        const columns = query(sql);
        bool has_admin;
        bool has_unsearchable;

        foreach (ref column; columns) {
            if (column.length < 1)
                continue;

            if (column[1] == "admin") {
                has_admin = true;
                continue;
            }

            if (column[1] == "unsearchable") {
                has_unsearchable = true;
                continue;
            }
        }

        if (!has_admin) {
            enum admin_sql = text(
                "ALTER TABLE ", users_table, " ADD COLUMN admin INTEGER;"
            );
            query(admin_sql);
        }

        if (!has_unsearchable) {
            enum unsearchable_sql = text(
                "ALTER TABLE ", users_table,
                " ADD COLUMN unsearchable INTEGER;"
            );
            query(unsearchable_sql);
        }
    }


    // Backup

    bool backup(string filename)
    {
        const normalized_filename = filename.absolutePath.buildNormalizedPath;
        if (normalized_filename == db_filename) {
            writeln("Backup path must not match the main database path");
            return false;
        }

        const tmp_filename = normalized_filename ~ ".tmp";
        enum sql = text("VACUUM INTO ?");

        try {
            if (exists(tmp_filename)) remove(tmp_filename);
            query(sql, [tmp_filename]);
            rename(tmp_filename, normalized_filename);

            writeln("Database backed up to ", normalized_filename);
        }
        catch (Exception e) {
            writeln(
                "Failed to back up database to ", normalized_filename, ": ",
                e.msg
            );
            return false;
        }
        return true;
    }


    // Config

    private void init_config()
    {
        enum sql = text(
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
        enum sql = text(
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
        enum sql = text(
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


    // Search Filters

    void filter_search_phrase(SearchFilterType type)(string phrase)
    {
        enum sql = text(
            "REPLACE INTO ",
            search_filters_table, "(type, phrase) VALUES(?, ?);"
        );
        query(sql, [text(cast(uint) type), phrase]);

        if (log_db) writeln(
            "DB: Filtered search phrase ", phrase, " ",
            type == SearchFilterType.server ? "server" : "client", "-side"
        );
    }

    void unfilter_search_phrase(SearchFilterType type)(string phrase)
    {
        enum sql = text(
            "DELETE FROM ", search_filters_table,
            " WHERE type = ? AND phrase = ?;"
        );
        query(sql, [text(cast(uint) type), phrase]);

        if (log_db) writeln(
            "DB: Unfiltered search phrase ", phrase, " ",
            type == SearchFilterType.server ? "server" : "client", "-side"
        );
    }

    void set_user_unsearchable(string username, bool unsearchable)
    {
        enum sql = text(
            "UPDATE ", users_table, " SET unsearchable = ? WHERE username = ?;"
        );

        query(
            sql, [unsearchable ? unsearchable.to!ubyte.text : null, username]
        );
    }

    string[] search_filters(SearchFilterType type)()
    {
        enum sql = text(
            "SELECT phrase FROM ", search_filters_table, " WHERE type = ?;"
        );

        Appender!(string[]) phrases;
        foreach (record ; query(sql, [text(cast(uint) type)]))
            phrases ~= record[0];

        return phrases[];
    }

    size_t num_search_filters(SearchFilterType type)()
    {
        enum sql = text(
            "SELECT COUNT(1) FROM ", search_filters_table, " WHERE type = ?;"
        );
        return query(sql, [(cast(uint) type).text])[0][0].to!size_t;
    }

    bool is_search_phrase_filtered(SearchFilterType type)(string phrase)
    {
        enum sql = text(
            "SELECT 1",
            " FROM ", search_filters_table, " WHERE type = ? AND phrase = ?;"
        );
        return query(sql, [text(cast(uint) type), phrase]).length > 0;
    }

    bool is_search_query_filtered(string search_query)
    {
        // For each filtered phrase, check if its words are present anywhere
        // in the search query
        enum insert_sql = text(
            "REPLACE INTO ", search_query_table, "(rowid, query) VALUES (1, ?)"
        );
        enum query_sql = text(
            "SELECT 1",
            " FROM ", search_filters_table,
            " WHERE type = ? AND phrase NOT LIKE '%  %' AND EXISTS(",
            "  SELECT 1",
            "  FROM ", search_query_table,
            "  WHERE query MATCH",
            "  '\"' ||",
            "   REPLACE(",
            "    REPLACE(", search_filters_table, ".phrase, '\"', '\"\"'),",
            "    ' ',",
            "    '\" AND \"'",
            "   )",
            "  || '\"'",
            " );"
        );

        query(insert_sql, [search_query]);
        return query(query_sql, [text(cast(uint) SearchFilterType.server)])
            .length > 0;
    }

    bool is_user_unsearchable(string username)
    {
        enum sql = text(
            "SELECT unsearchable FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        bool unsearchable;

        if (res.length > 0)
            try unsearchable = cast(bool) res[0][0].to!ubyte;
            catch (ConvException) {}

        return unsearchable;
    }


    // Users

    void add_user(string username, string hash)
    {
        enum sql = text(
            "INSERT INTO ", users_table, "(username, password) VALUES(?, ?);"
        );
        query(sql, [username, hash]);
        query("PRAGMA optimize;");

        if (log_user) writeln("Added new user ", blue, username, norm);
    }

    void del_user(string username)
    {
        enum sql = text("DELETE FROM ", users_table, " WHERE username = ?;");
        query(sql, [username]);

        if (log_user) writeln("Removed user ", blue, username, norm);
    }

    string user_password_hash(string username)
    {
        enum sql = text(
            "SELECT password FROM ", users_table, " WHERE username = ?;"
        );
        return query(sql, [username])[0][0];
    }

    void user_update_password(string username, string hash)
    {
        enum sql = text(
            "UPDATE ", users_table, " SET password = ? WHERE username = ?;"
        );
        query(sql, [hash, username]);

        if (log_user) writeln(
            "Updated user ", blue, username, norm, "'s password"
        );
    }

    bool user_exists(string username)
    {
        enum sql = text(
            "SELECT 1 FROM ", users_table, " WHERE username = ?;"
        );
        return query(sql, [username]).length > 0;
    }

    void add_admin(string username, Duration duration)
    {
        enum sql = text(
            "UPDATE ", users_table, " SET admin = ? WHERE username = ?;"
        );
        long admin_until;

        if (duration == Duration.max)
            admin_until = long.max;
        else
            admin_until = (
                Clock.currTime.toUnixTime + duration.total!"seconds");

        query(sql, [admin_until.text, username]);

        if (log_user) writeln("Added admin ", blue, username, norm);
    }

    void del_admin(string username)
    {
        enum sql = text(
            "UPDATE ", users_table, " SET admin = ? WHERE username = ?;"
        );
        query(sql, [null, username]);

        if (log_user) writeln("Removed admin ", blue, username, norm);
    }

    SysTime admin_until(string username)
    {
        enum sql = text(
            "SELECT admin FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        long admin_until;

        if (res.length > 0) {
            try admin_until = res[0][0].to!long;
            catch (ConvException) {}
        }

        if (admin_until == 0)
            return SysTime();

        if (admin_until >= SysTime.max.toUnixTime)
            return SysTime.max;

        return SysTime.fromUnixTime(admin_until, UTC());
    }

    void add_user_privileges(string username, Duration duration)
    {
        enum sql = text(
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

        enum sql = text(
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
        enum sql = text(
            "SELECT privileges FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        long privileged_until;

        if (res.length > 0) {
            try privileged_until = res[0][0].to!long;
            catch (ConvException) {}
        }

        if (privileged_until == 0)
            return SysTime();

        if (privileged_until >= SysTime.max.toUnixTime)
            return SysTime.max;

        return SysTime.fromUnixTime(privileged_until, UTC());
    }

    void ban_user(string username, Duration duration)
    {
        enum sql = text(
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
        enum sql = text(
            "UPDATE ", users_table, " SET banned = ? WHERE username = ?;"
        );
        query(sql, [null, username]);

        if (log_user) writeln("Unbanned user ", blue, username, norm);
    }

    SysTime user_banned_until(string username)
    {
        enum sql = text(
            "SELECT banned FROM ", users_table, " WHERE username = ?;"
        );
        const res = query(sql, [username]);
        long banned_until;

        if (res.length > 0) {
            try banned_until = res[0][0].to!long;
            catch (ConvException) {}
        }

        if (banned_until == 0)
            return SysTime();

        if (banned_until >= SysTime.max.toUnixTime)
            return SysTime.max;

        return SysTime.fromUnixTime(banned_until, UTC());
    }

    SdbUserStats user_stats(string username)
    {
        enum sql = text(
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


    // Rooms

    void add_room(string room_name, string owner = null)
    {
        enum sql = text(
            "INSERT OR IGNORE INTO ", rooms_table,
            "(room, type, owner) VALUES(?, ?, ?);"
        );
        const type = (owner !is null) ? RoomType._private : RoomType._public;

        query(sql, [room_name, text(cast(int) type), owner]);
    }

    void del_room(string room_name)
    {
        enum sql = text("DELETE FROM ", rooms_table, " WHERE room = ?;");
        query(sql, [room_name]);
    }

    RoomType get_room_type(string room_name)
    {
        enum sql = text(
            "SELECT type FROM ", rooms_table, " WHERE room = ?;"
        );
        const res = query(sql, [room_name]);
        if (res.length > 0)
            return cast(RoomType) res[0][0].to!int;
        return RoomType.non_existent;
    }

    string get_room_owner(string room_name)
    {
        enum sql = text(
            "SELECT owner FROM ", rooms_table, " WHERE room = ? AND type = ?;"
        );
        const res = query(sql, [room_name, text(cast(int) RoomType._private)]);
        return res.length > 0 ? res[0][0] : null;
    }

    bool is_room_member(string room_name, string username)
    {
        enum sql = text(
            "SELECT 1 FROM ", rooms_table, " WHERE room = ? AND owner = ?",
            " UNION ALL ",
            "SELECT 1 FROM ", room_members_table,
            " WHERE room = ? AND username = ?"
        );
        const res = query(sql, [room_name, username, room_name, username]);
        return res.length > 0;
    }

    string[] rooms(string owner = null,
                   string member = null,
                   RoomMemberType member_type = RoomMemberType.any)
    {
        Appender!(string[]) rooms;
        auto sql = text("SELECT r.room FROM ", rooms_table, " r");
        string[] parameters;

        if (owner !is null) {
            sql ~= text(" WHERE r.type = ? AND r.owner = ?");
            parameters ~= [text(cast(uint) RoomType._private), owner];
        }
        else if (member !is null) {
            sql ~= text(
                " JOIN ", room_members_table, " m ON r.room = m.room",
                " WHERE r.type = ? AND m.username = ?"
            );
            parameters ~= [text(cast(uint) RoomType._private), member];

            if (member_type != RoomMemberType.any) {
                sql ~= " AND m.type = ?";
                parameters ~= [text(cast(uint) member_type)];
            }
        }
        else {
            sql ~= text(" WHERE r.type = ?");
            parameters ~= [text(cast(uint) RoomType._public)];
        }
        sql ~= ";";

        foreach (record ; query(sql, parameters)) rooms ~= record[0];
        return rooms[];
    }

    void add_room_member(RoomMemberType type)(string room_name,
                                              string username)
    {
        if (type < 0)
            return;

        enum sql = text(
            "REPLACE INTO ", room_members_table,
            "(room, username, type) VALUES(?, ?, ?);"
        );
        query(sql, [room_name, username, text(cast(int) type)]);
    }

    void del_room_member(string room_name, string username)
    {
        enum sql = text(
            "DELETE FROM ", room_members_table,
            " WHERE room = ? AND username = ?;"
        );
        query(sql, [room_name, username]);
    }

    RoomMemberType get_room_member_type(string room_name, string username)
    {
        enum sql = text(
            "SELECT m.type FROM ", room_members_table, " m",
            " JOIN ", rooms_table, " r ON m.room = r.room",
            " WHERE r.room = ? AND r.type = ? AND m.username = ?;"
        );
        const res = query(sql, [
            room_name,
            text(cast(int) RoomType._private),
            username
        ]);
        if (res.length > 0)
            return cast(RoomMemberType) res[0][0].to!int;
        return RoomMemberType.non_existent;
    }

    string[] room_members(RoomMemberType type)(string room_name)
    {
        Appender!(string[]) members;
        auto sql = text(
            "SELECT m.username FROM ", room_members_table, " m",
            " JOIN ", rooms_table, " r ON m.room = r.room",
            " WHERE r.room = ? AND r.type = ?"
        );
        auto parameters = [room_name, text(cast(int) RoomType._private)];

        if (type != RoomMemberType.any) {
            sql ~= " AND m.type = ?";
            parameters ~= [text(cast(int) type)];
        }
        sql ~= ";";

        const res = query(sql, parameters);
        foreach (ref record ; res) members ~= record[0];
        return members[];
    }

    void add_ticker(string room_name, string username, string content)
    {
        enum sql = text(
            "INSERT INTO ", tickers_table,
            "(room, username, content) VALUES(?, ?, ?);"
        );
        query(sql, [room_name, username, content]);
    }

    string get_ticker(string room_name, string username)
    {
        enum sql = text(
            "SELECT content FROM ", tickers_table,
            " WHERE room = ? AND username = ?;"
        );
        const res = query(sql, [room_name, username]);
        return res.length > 0 ? res[0][0] : null;
    }

    void del_ticker(string room_name, string username)
    {
        enum sql = text(
            "DELETE FROM ", tickers_table, " WHERE room = ? AND username = ?;"
        );
        query(sql, [room_name, username]);
    }

    string del_oldest_ticker(string room_name)
    {
        enum sql = text(
            "SELECT username FROM ", tickers_table, " WHERE room = ? LIMIT 1;"
        );
        const res = query(sql, [room_name]);
        string username;

        if (res.length > 0) {
            username = res[0][0];
            del_ticker(room_name, username);
        }
        return username;
    }

    string[][] room_tickers(string room_name)
    {
        enum sql = text(
            "SELECT username, content FROM ", tickers_table,
            " WHERE room = ?",
            " ORDER BY rowid;"
        );
        return query(sql, [room_name]);
    }

    string[][] user_tickers(RoomType type)(string username)
    {
        auto sql = text(
            "SELECT t.room, t.content FROM ", tickers_table, " t",
            " JOIN ", rooms_table, " r ON t.room = r.room",
            " WHERE t.username = ?"
        );
        auto parameters = [username];

        if (type != RoomType.any) {
            sql ~= " AND r.type = ?";
            parameters ~= [text(cast(int) type)];
        }
        sql ~= " ORDER BY t.rowid;";

        return query(sql, parameters);
    }

    ulong num_room_tickers(string room_name)
    {
        enum sql = text(
            "SELECT COUNT(1) FROM ", tickers_table, " WHERE room = ?;"
        );
        const res = query(sql, [room_name]);
        return res.length > 0 ? res[0][0].to!ulong : 0;
    }


    // SQLite

    private void raise_sql_error(string query = null,
                                 string[] parameters = null,
                                 int res = 0)
    {
        const error_code = extended_error_code;
        const error_string = error_string(error_code);

        if (query)
            writeln("DB: Query [", query, "]");

        if (parameters)
            writeln("DB: Parameters [", parameters.join(", "), "]");

        if (res)
            writeln("DB: Result code ", res, ".\n\n", error_msg, "\n");

        throw new SdbException(
            text("SQLite error ", error_code, " (", error_string, ")")
        );
    }

    private string[][] query(string query, string[] parameters = null)
    {
        Appender!(string[][]) ret;
        sqlite3_stmt* stmt;

        int res = prepare(query, stmt);
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
    string sqlite_version()
    {
        return sqlite3_libversion.fromStringz.idup;
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
    private void db_config(int option, int value)
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
    private int extended_error_code()
    {
        return sqlite3_extended_errcode(db);
    }

    @trusted
    private string error_msg()
    {
        return sqlite3_errmsg(db).fromStringz.idup;
    }

    @trusted
    private string error_string(int error_code)
    {
        return sqlite3_errstr(error_code).fromStringz.idup;
    }

    @trusted
    private int prepare(string query, out sqlite3_stmt* statement)
    {
        return sqlite3_prepare_v2(
            db, query.toStringz, cast(int) query.length, &statement, null
        );
    }

    @trusted
    private static int bind_null(sqlite3_stmt* statement, int index)
    {
        return sqlite3_bind_null(statement, index);
    }

    @trusted
    private static int bind_text(sqlite3_stmt* statement, int index,
                                 string value)
    {
        return sqlite3_bind_text(
            statement, index, value.toStringz, cast(int) value.length, null
        );
    }

    @trusted
    private static int column_count(sqlite3_stmt* statement)
    {
        return sqlite3_column_count(statement);
    }

    @trusted
    private static int step(sqlite3_stmt* statement)
    {
        return sqlite3_step(statement);
    }

    @trusted
    private static string column_text(sqlite3_stmt* statement, int index)
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
