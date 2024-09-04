// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module db;
@safe:

import defines;

import std.string : format, join, split, replace, toStringz;
import std.stdio : writeln, write;
import std.file : exists, isFile, getAttributes;
import std.conv : to, octal, ConvException;

import etc.c.sqlite3;

class Sdb
{
	sqlite3* db;
	sqlite3_stmt* stmt;

	const string users_table  = "users";
	const string admins_table = "admins";
	const string config_table   = "config";

	const string users_table_format  = "CREATE TABLE IF NOT EXISTS %s(username TEXT PRIMARY KEY, password TEXT, speed INTEGER, ulnum INTEGER, files INTEGER, folders INTEGER, banned INTEGER, privileges INTEGER) WITHOUT ROWID;";
	const string admins_table_format = "CREATE TABLE IF NOT EXISTS %s(username TEXT PRIMARY KEY, level INTEGER) WITHOUT ROWID;";
	const string config_table_format   = "CREATE TABLE IF NOT EXISTS %s(option TEXT PRIMARY KEY, value) WITHOUT ROWID;";

	this(string file, bool update = false)
	{
		open_db(file);

		if (!exists(file) || !isFile(file)) {
			throw new Exception("Cannot create database file %s".format(file));
			return;
		}
		query(format(users_table_format,  users_table));
		query(format(admins_table_format, admins_table));
		init_config();
	}

	@trusted
	void open_db(string file)
	{
		sqlite3_open(file.toStringz(), &db);
	}

	void add_admin(string username, uint level = 0)
	{
		this.query(format("REPLACE INTO %s(username, level) VALUES('%s', %d);", admins_table, escape(username), level));
	}

	void del_admin(string username)
	{
		this.query(format("DELETE FROM %s WHERE username = '%s';", admins_table, escape(username)));
	}

	string[] get_admins()
	{
		string[][] res = this.query(format("SELECT username FROM %s;", admins_table));
		string[] ret;

		foreach (string[] record ; res) ret ~= record[0];
		return ret;
	}

	bool is_admin(string username)
	{
		string[][] res = this.query("SELECT username FROM %s WHERE username = '%s';".format(admins_table, escape(username)));
		return to!bool(res.length);
	}

	void init_config()
	{
		query(config_table_format.format(config_table));

		init_config_option("port", port);
		init_config_option("max_users", max_users);
		init_config_option("motd", "Soulfind %sversion%");
	}

	void init_config_option(string option, string value)
	{
		query("INSERT OR IGNORE INTO %s(option, value) VALUES('%s', '%s');".format(config_table, option, escape(value)));
	}

	void init_config_option(string option, uint value)
	{
		query("INSERT OR IGNORE INTO %s(option, value) VALUES('%s', %d);".format(config_table, option, value));
	}

	void set_config_value(string option, string value)
	{
		query("REPLACE INTO %s(option, value) VALUES('%s', '%s');".format(config_table, option, escape(value)));
	}

	void set_config_value(string option, uint value)
	{
		query("REPLACE INTO %s(option, value) VALUES('%s', %d);".format(config_table, option, value));
	}

	string get_config_value(string option)
	{
		string[][] res = query("SELECT value FROM %s WHERE option = '%s';".format(config_table, option));
		return res[0][0];
	}

	uint nb_users()
	{
		string query = "SELECT COUNT(username) FROM %s;".format(users_table);
		string[][] res = this.query(query);
		return atoi(res[0][0]);
	}

	uint nb_banned_users()
	{
		string query = "SELECT COUNT(username) FROM %s WHERE banned = 1;".format(users_table);
		string[][] res = this.query(query);
		return atoi(res[0][0]);
	}

	string[] get_banned_usernames()
	{
		string[][] res = this.query("SELECT username FROM %s WHERE banned = 1;".format(users_table));
		string[] ret;

		foreach (string[] record ; res) ret ~= record[0];
		return ret;
	}

	void user_update_field(string username, string field, string value)
	{
		string query = "UPDATE %s SET %s = '%s' WHERE username = '%s';".format(users_table, field, escape(value), escape(username));

		this.query(query);
	}

	void user_update_field(string username, string field, uint value)
	{
		string query = "UPDATE %s SET %s = %d WHERE username = '%s';".format(users_table, field, value, escape(username));

		this.query(query);
	}

	string[] get_all_usernames()
	{
		string[][] res = this.query("SELECT username FROM %s;".format(users_table));
		string[] ret;

		foreach (string[] record ; res) ret ~= record[0];
		return ret;
	}

	bool user_exists(string username)
	{
		string[][] res = this.query(format("SELECT username FROM %s WHERE username = '%s';", users_table, escape(username)));
		return res.length > 0;
	}

	string get_pass(string username)
	{
		string[][] res = this.query(format("SELECT password FROM %s WHERE username = '%s';", users_table, escape(username)));
		return res[0][0];
	}

	void add_user(string username, string password)
	{
		string query = "INSERT INTO %s(username, password) VALUES('%s', '%s');".format(
			users_table, escape(username), escape(password)
		);
		this.query(query);
		debug(db) writeln(query);
	}

	bool is_banned(string username)
	{
		string query = "SELECT banned FROM %s WHERE username = '%s';".format(
			users_table, escape(username)
		);
		string[][] res = this.query(query);

		if (res.length == 1)
			return(atoi(res[0][0]) != 0);

		return false;
	}

	bool get_user(string username, out uint speed, out uint upload_number, out uint something, out uint shared_files, out uint shared_folders)
	{
		debug(db) writeln("DB: Requested ", username, "'s info...");
		string query = "SELECT speed,ulnum,files,folders FROM %s WHERE username = '%s';".format(
			users_table, escape(username)
		);
		string[][] res = this.query(query);
		if (res.length > 0) {
			string[] u      = res[0];

			speed           = atoi(u[0]);
			upload_number   = atoi(u[1]);
			shared_files    = atoi(u[2]);
			shared_folders  = atoi(u[3]);
			something       = 0;
			return true;
		}
		return false;
	}

	bool get_user(string username, string password, out uint speed, out uint upload_number, out uint shared_files, out uint shared_folders, out uint privileges)
	{
		debug(db) writeln("DB: Requested ", username, "'s info...");
		string query = "SELECT speed,ulnum,files,folders,privileges FROM %s WHERE username = '%s' AND password = '%s';".format(
			users_table, escape(username), escape(password)
		);
		string[][] res = this.query(query);
		if (res.length > 0) {
			string[] u      = res[0];

			speed           = atoi(u[0]);
			upload_number   = atoi(u[1]);
			shared_files    = atoi(u[2]);
			shared_folders  = atoi(u[3]);
			privileges      = atoi(u[4]);
			return true;
		}
		return false;
	}

	@trusted
	string[][] query(string query)
	{
		string[][] ret;
		char* tail;
		uint res;
		uint fin;

		debug(db) writeln("DB: Query [", query, "]");
		sqlite3_prepare_v2(db, query.toStringz(), cast(uint)query.length, &stmt, &tail);

		res = sqlite3_step(stmt);

		while(res == SQLITE_ROW) {
			string[] record;
			uint n = sqlite3_column_count(stmt);

			for(uint i ; i < n ; i++) record ~= to!string(sqlite3_column_text(stmt, i));

			ret ~= record;
			res = sqlite3_step(stmt);
		}

		fin = sqlite3_finalize(stmt);

		if (res != SQLITE_DONE || fin != SQLITE_OK) {
			// https://sqlite.org/rescode.html#extrc
			debug(db) writeln(format("DB: Result Code %d (%s)", res, sqlite3_errstr(res).to!string));
			debug(db) writeln(format("    >Final Code %d (%s)", fin, sqlite3_errstr(fin).to!string));
			throw new Exception(sqlite3_errstr(fin).to!string);
			return null;
		}
		return ret;
	}

	string escape(string str)
	{
		return replace(str, "'", "''");
	}

	uint atoi(string str)
	{
		if (str == "")
			return 0;

		try {
			uint i = to!uint(str);
			return i;
		}
		catch (ConvException e) {
			return 0;
		}
	}
}
