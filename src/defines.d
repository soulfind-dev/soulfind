module defines;

int port      = 2240;
int max_users = 65535;

version (Windows)
	{
	static string VERSION	= "0.4.8 win";
	string default_db_file	= "soulfind.db";
	}
else
	{
	static string VERSION	= "0.4.8";
	string default_db_file	= "/var/db/soulfind/soulfind.db";
	}


// colours
version (Windows)
	{ // The Windows console doesn't understand these colour codes
	const char[] blue      = "";
	const char[] black     = "";
	const char[] red       = "";
	const char[] underline = "";
	}
else
	{
	const char[] blue      = "\033[01;94m";
	const char[] black     = "\033[0m";
	const char[] red       = "\033[01;91m";
	const char[] underline = "\033[04;30m";
	}

