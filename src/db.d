module db;

import defines;

private import log : log;

private import std.string : format, join, split, replace, toStringz;
private import std.file : exists, isFile, getAttributes;
private import std.conv : to, octal, ConvException;

private import sqlite3_imp;

class Sdb
	{
	sqlite3* db;
	sqlite3_stmt* stmt;

	string users_table  = "users";
	string admins_table = "admins";
	string conf_table   = "conf";

	string users_table_format  = "CREATE TABLE %s (username TEXT, password TEXT, speed INTEGER, dlnum INTEGER, files INTEGER, folders INTEGER, banned INTEGER, privileges INTEGER);";
	string admins_table_format = "CREATE TABLE %s (username TEXT, level INTEGER);";
	string conf_table_format   = "CREATE TABLE %s (port INTEGER, max_users INTEGER, max_message_size INTEGER, max_offline_pms INTEGER, motd TEXT, server_user TEXT, case_insensitive INTEGER, md5_ident INTEGER);";

	this (string file, bool update = false)
		{
		string default_conf_format = format ("INSERT INTO %%s (port, max_users, max_message_size, max_offline_pms, motd, server_user, case_insensitive, md5_ident) VALUES (%d, %d, %d, %d, 'Soulfind %s', '%s', %d, %d);", 2240, 65535, 16384, 15, VERSION, "server", 0, 1);
		if (!exists (file) || !isFile (file))
			{
			sqlite3_open (file.toStringz(), &db);
			if (!exists (file) || !isFile (file))
				{
				throw new Exception ("Cannot create database file " ~ file);
				return;
				}
			this.query (format (users_table_format,  users_table));
			this.query (format (admins_table_format, admins_table));
			this.query (format (conf_table_format,   conf_table));
			this.query (format (default_conf_format, conf_table));
			}
		else
			{
			version (linux)
				{
				uint a = getAttributes (file);
				if (!((a & octal!700) >> 6 & 0b010))
					{
					throw new Exception ("Database file (" ~ file ~ ") not writable");
					return;
					}
				}
			
			sqlite3_open (file.toStringz(), &db);
			string[][] res = this.query (format ("SELECT sql FROM sqlite_master WHERE name = '%s';", conf_table));
			if (res[0][0] != format (conf_table_format[0 .. $-1], conf_table))
				{
				update_conf_table (res[0][0], default_conf_format[0 .. $-1]);
				log(1, "Configuration updated.");
				}
			}
		}
	
		// argh, I never realised that ALTER TABLE was so useful
	void update_conf_table (string creation_string, string default_conf_format)
		{
		string old_fields = join (parse_db_format (creation_string), ",");
		
		this.query (format (conf_table_format, "tmp_conf"));		// create a temp table
		this.query (format (default_conf_format, "tmp_conf"));		// fill it with the default values
		this.query (format ("INSERT INTO tmp_conf (%s) SELECT %s FROM %s;", old_fields, old_fields, conf_table)); // fetch the already existing values into the temp table
		this.query (format ("DROP TABLE %s;", conf_table));		// delete the old configuration table
		this.query (format (conf_table_format, conf_table));		// re-create it, with the new format now
		this.query (format ("INSERT INTO %s SELECT * FROM tmp_conf;", conf_table));	// fetch the temp table values into the new configuration table
		this.query (format ("DROP TABLE tmp_conf"));			// and finally drop the temp table...
		}
	
		// my eyes are bleeding !
	string[] parse_db_format (string f)
		{ // format is like "CREATE TABLE conf (port integer, max_users integer, max_message_size integer, max_offline_pms integer)"
		string[] res = split (f);
		res = res[3 .. $];       // remove "CREATE TABLE conf"
		res[0] = res[0][1 .. $]; // remove '('

		string[] ret;
		ret.length = res.length/2;
		for (int i = 0 ; i < ret.length ; i++)
			{
			ret[i] = res[i*2];
			}

		return ret;
		}
	
	void add_admin (string username, int level = 0)
		{
		this.query (format ("INSERT INTO %s (username, level) VALUES ('%s', %d);", admins_table, escape (username), level));
		}
	
	void del_admin (string username)
		{
		this.query (format ("DELETE FROM %s WHERE username = '%s';", admins_table, escape (username)));
		}
	
	string[] get_admins ()
		{
		string[][] res = this.query (format ("SELECT username FROM %s;", admins_table));

		string[] ret;

		foreach (string[] record ; res)
			{
			ret ~= record[0];
			}

		return ret;
		}
	
	void conf_set_field (string field, int value)
		{
		this.query (format ("UPDATE %s SET '%s' = %d;", conf_table, field, value));
		}
	
	void conf_set_field (string field, string value)
		{
		this.query (format ("UPDATE %s SET '%s' = '%s';", conf_table, field, escape (value)));
		}
	
	int conf_get_int (string field)
		{
		string[][] res = this.query (format ("SELECT %s FROM %s;", field, conf_table));

		return to!int(res[0][0]);
		}
	
	string conf_get_str (string field)
		{
		string[][] res = this.query (format ("SELECT %s FROM %s;", field, conf_table));

		return res[0][0];
		}

	int nb_users ()
		{
		string query = format ("SELECT COUNT(username) FROM %s;", users_table);
		string[][] res = this.query (query);
		return atoi (res[0][0]);
		}
	
	int nb_banned_users ()
		{
		string query = format ("SELECT COUNT(username) FROM %s WHERE banned = 1;", users_table);
		string[][] res = this.query (query);
		return atoi (res[0][0]);
		}

	string[] get_banned_usernames ()
		{
		string[][] res = this.query (format ("SELECT username FROM %s WHERE banned = 1;", users_table));

		string[] ret;

		foreach (string[] record ; res)
			{
			ret ~= record[0];
			}

		return ret;
		}

	void user_update_field (string username, string field, string value)
		{
		string query = format ("UPDATE %s SET %s = '%s' WHERE username = '%s';", users_table, field, escape (value), escape (username));

		this.query (query);
		}

	void user_update_field (string username, string field, int value)
		{
		string query = format ("UPDATE %s SET %s = %d WHERE username = '%s';", users_table, field, value, escape (username));

		this.query (query);
		}

	string[] get_all_usernames ()
		{
		string[][] res = this.query (format ("SELECT username FROM %s;", users_table));

		string[] ret;

		foreach (string[] record ; res)
			{
			ret ~= record[0];
			}

		return ret;
		}
	
	bool user_exists (string username)
		{
		string[][] res = this.query (format ("SELECT username FROM %s WHERE username = '%s';", users_table, escape (username)));

		if (res.length > 0) return true;
		else                return false;
		}
	
	string get_pass (string username)
		{
		string[][] res = this.query (format ("SELECT password FROM %s WHERE username = '%s';", users_table, escape (username)));

		if (res.length > 0) return res[0][0];
		else                throw new Exception ("User " ~ username ~ " does not exist");
		}
	
	void add_user (string username, string password)
		{
			{
			string query = format ("INSERT INTO %s (username, password) VALUES ('%s', '%s');",
					       users_table, escape (username), escape (password));
			this.query (query);
			log(4, query);
			}
		}
	
	bool is_banned (string username)
		{
		string query = format ("SELECT banned FROM %s WHERE username = '%s';", users_table, escape (username));
		string[][] res = this.query (query);

		if (res.length == 1)
			{
			return (atoi (res[0][0]) != 0);
			}
		else // if the user doesn't exist, he isn't banned...
			{
			return false;
			}
		}
	
	bool get_user (string username, out int speed, out int download_number, out int something, out int shared_files, out int shared_folders)
		{
		log(4, "DB: Requested ", username, "'s info...");
		string query = format ("SELECT speed,dlnum,files,folders FROM %s WHERE username = '%s';", users_table, escape (username));
		string[][] res = this.query (query);
		if (res.length > 0)
			{
			string[] u           = res[0];

			speed           = atoi (u[0]);
			download_number = atoi (u[1]);
			shared_files    = atoi (u[2]);
			shared_folders  = atoi (u[3]);
			something       = 1789;
			return true;
			}
		else
			{
			return false;
			}
		}
	
	bool get_user (string username, out string password, out int speed, out int download_number, out int shared_files, out int shared_folders, out int privileges)
		{
		log(4, "DB: Requested ", username, "'s info...");
		string query = format ("SELECT password,speed,dlnum,files,folders,privileges FROM %s WHERE username = '%s';", users_table, escape (username));
		string[][] res = this.query (query);
		if (res.length > 0)
			{
			string[] u           = res[0];

			password        = u[0];
			speed           = atoi (u[1]);
			download_number = atoi (u[2]);
			shared_files    = atoi (u[3]);
			shared_folders  = atoi (u[4]);
			privileges      = atoi (u[5]);
			return true;
			}
		else
			{
			return false;
			}
		}

	string get_insensitive_username (string username)
		{
		string[][] res = query (format ("SELECT username FROM %s WHERE username LIKE '%s'", users_table, escape (username)));
		
		if (res.length > 0) return res[0][0];
		else		    return null;
		}
	
	string[][] query (string query)
		{
		log(4, "DB query : \"", query, "%s\"");
		string[][] ret;
		
		sqlite3_reset (stmt);
		
		char* tail;

		sqlite3_prepare (db, query.toStringz(), cast(int)query.length, &stmt, &tail);

		int res;
		res = sqlite3_step (stmt);

		while (res == SQLITE_ROW)
			{
			string[] record;
			int n = sqlite3_column_count (stmt);

			for (int i ; i < n ; i++)
				{
				record ~= to!string(sqlite3_column_text (stmt, i));
				}

			ret ~= record;
			res = sqlite3_step (stmt);
			}

		if (res != SQLITE_DONE)
			{
			throw new Exception (format ("SQL Error nb %d, query was : \"%s\"", res, query));
			return null;
			}

		return ret;
		}

	string escape (string str)
		{
		return replace (str, "'", "''");
		}

	int atoi (string str)
		{
		if (str == "")
			{
			return 0;
			}
		
		try
			{
			int i = to!int(str);
			return i;
			}
		catch (ConvException e)
			{
			return 0;
			}
		}
	}
