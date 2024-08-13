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
	const string conf_table   = "conf";

	const string users_table_format  = "CREATE TABLE %s(username TEXT, password TEXT, speed INTEGER, ulnum INTEGER, files INTEGER, folders INTEGER, banned INTEGER, privileges INTEGER);";
	const string admins_table_format = "CREATE TABLE %s(username TEXT, level INTEGER);";
	const string conf_table_format   = "CREATE TABLE %s(port INTEGER, max_users INTEGER, motd TEXT);";

	this(string file, bool update = false)
	{
		string default_conf_format = format("INSERT INTO %%s(port, max_users, motd) VALUES(%d, %d, 'Soulfind %s');", port, max_users, VERSION);
		if (!exists(file) || !isFile(file)) {
			open_db(file);
			if (!exists(file) || !isFile(file)) {
				throw new Exception("Cannot create database file " ~ file);
				return;
			}
			query(format(users_table_format,  users_table));
			query(format(admins_table_format, admins_table));
			query(format(conf_table_format,   conf_table));
			query(format(default_conf_format, conf_table));
		}
		else {
			open_db(file);

			string[][] res = query(format("SELECT sql FROM sqlite_master WHERE name = '%s';", conf_table));
			if (res[0][0] != format(conf_table_format[0 .. $-1], conf_table)) {
				write("Configuration needs to be updated... ");
				update_conf_table(res[0][0], default_conf_format[0 .. $-1]);
				writeln("updated.");
			}
		}
	}

	@trusted
	void open_db(string file)
	{
		sqlite3_open(file.toStringz(), &db);
	}

	// argh, I never realised that ALTER TABLE was so useful
	void update_conf_table(string creation_string, string default_conf_format)
	{
		string old_fields = join(parse_db_format(creation_string), ",");
		
		query(format(conf_table_format, "tmp_conf"));		// create a temp table
		query(format(default_conf_format, "tmp_conf"));		// fill it with the default values
		query(format("INSERT INTO tmp_conf(%s) SELECT %s FROM %s;", old_fields, old_fields, conf_table)); // fetch the already existing values into the temp table
		query(format("DROP TABLE %s;", conf_table));		// delete the old configuration table
		query(format(conf_table_format, conf_table));		// re-create it, with the new format now
		query(format("INSERT INTO %s SELECT * FROM tmp_conf;", conf_table));	// fetch the temp table values into the new configuration table
		query(format("DROP TABLE tmp_conf"));			// and finally drop the temp table...
	}
	
	// my eyes are bleeding !
	string[] parse_db_format(string f)
	{ // format is like "CREATE TABLE conf(port integer, max_users integer)"
		string[] res = split(f);
		res = res[3 .. $];       // remove "CREATE TABLE conf"
		res[0] = res[0][1 .. $]; // remove '('

		string[] ret;
		ret.length = res.length/2;
		for(uint i = 0 ; i < ret.length ; i++) ret[i] = res[i*2];
		return ret;
	}
	
	void add_admin(string username, uint level = 0)
	{
		this.query(format("INSERT INTO %s(username, level) VALUES('%s', %d);", admins_table, escape(username), level));
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
	
	void conf_set_field(string field, uint value)
	{
		this.query(format("UPDATE %s SET '%s' = %d;", conf_table, field, value));
	}
	
	void conf_set_field(string field, string value)
	{
		this.query(format("UPDATE %s SET '%s' = '%s';", conf_table, field, escape(value)));
	}
	
	uint conf_get_int(string field)
	{
		string[][] res = this.query(format("SELECT %s FROM %s;", field, conf_table));
		return to!uint(res[0][0]);
	}
	
	string conf_get_str(string field)
	{
		string[][] res = this.query(format("SELECT %s FROM %s;", field, conf_table));
		return res[0][0];
	}

	uint nb_users()
	{
		string query = format("SELECT COUNT(username) FROM %s;", users_table);
		string[][] res = this.query(query);
		return atoi(res[0][0]);
	}
	
	uint nb_banned_users()
	{
		string query = format("SELECT COUNT(username) FROM %s WHERE banned = 1;", users_table);
		string[][] res = this.query(query);
		return atoi(res[0][0]);
	}

	string[] get_banned_usernames()
	{
		string[][] res = this.query(format("SELECT username FROM %s WHERE banned = 1;", users_table));
		string[] ret;

		foreach (string[] record ; res) ret ~= record[0];
		return ret;
	}

	void user_update_field(string username, string field, string value)
	{
		string query = format("UPDATE %s SET %s = '%s' WHERE username = '%s';", users_table, field, escape(value), escape(username));

		this.query(query);
	}

	void user_update_field(string username, string field, uint value)
	{
		string query = format("UPDATE %s SET %s = %d WHERE username = '%s';", users_table, field, value, escape(username));

		this.query(query);
	}

	string[] get_all_usernames()
	{
		string[][] res = this.query(format("SELECT username FROM %s;", users_table));
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
		if (res.length > 0)
			return res[0][0];

		throw new Exception("User " ~ username ~ " does not exist");
	}
	
	void add_user(string username, string password)
	{
		string query = format("INSERT INTO %s(username, password) VALUES('%s', '%s');",
				       users_table, escape(username), escape(password));
		this.query(query);
		debug(db) writeln(query);
	}
	
	bool is_banned(string username)
	{
		string query = format("SELECT banned FROM %s WHERE username = '%s';", users_table, escape(username));
		string[][] res = this.query(query);

		if (res.length == 1)
			return(atoi(res[0][0]) != 0);

		return false;
	}

	bool get_user(string username, out uint speed, out uint upload_number, out uint something, out uint shared_files, out uint shared_folders)
	{
		debug(db) writeln("DB: Requested ", username, "'s info...");
		string query = format("SELECT speed,ulnum,files,folders FROM %s WHERE username = '%s';", users_table, escape(username));
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
	
	bool get_user(string username, out string password, out uint speed, out uint upload_number, out uint shared_files, out uint shared_folders, out uint privileges)
	{
		debug(db) writeln("DB: Requested ", username, "'s info...");
		string query = format("SELECT password,speed,ulnum,files,folders,privileges FROM %s WHERE username = '%s';", users_table, escape(username));
		string[][] res = this.query(query);
		if (res.length > 0) {
			string[] u      = res[0];

			password        = u[0];
			speed           = atoi(u[1]);
			upload_number   = atoi(u[2]);
			shared_files    = atoi(u[3]);
			shared_folders  = atoi(u[4]);
			privileges      = atoi(u[5]);
			return true;
		}
		return false;
	}

	@trusted
	string[][] query(string query)
	{
		debug(db) writeln("DB query : \"", query, "%s\"");
		string[][] ret;
		
		sqlite3_reset(stmt);
		
		char* tail;

		sqlite3_prepare(db, query.toStringz(), cast(uint)query.length, &stmt, &tail);

		uint res;
		res = sqlite3_step(stmt);

		while(res == SQLITE_ROW) {
			string[] record;
			uint n = sqlite3_column_count(stmt);

			for(uint i ; i < n ; i++) record ~= to!string(sqlite3_column_text(stmt, i));

			ret ~= record;
			res = sqlite3_step(stmt);
		}

		if (res != SQLITE_DONE) {
			throw new Exception(format("SQL Error nb %d, query was : \"%s\"", res, query));
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
