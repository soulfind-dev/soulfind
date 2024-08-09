/+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 + SoulFind - Free SoulSeek server                                           +
 +                                                                           +
 + Copyright (C) 2005 SeeSchloss <seeschloss@seeschloss.org>                 +
 +                                                                           +
 + This  program  is free software ; you can  redistribute it  and/or modify +
 + it under  the  terms of  the GNU General Public License  as published  by +
 + the  Free  Software  Foundation ;  either  version  2 of  the License, or +
 + (at your option) any later version.                                       +
 +                                                                           +
 + This  program  is  distributed  in the  hope  that  it  will  be  useful, +
 + but   WITHOUT  ANY  WARRANTY ;  without  even  the  implied  warranty  of +
 + MERCHANTABILITY   or   FITNESS   FOR   A   PARTICULAR  PURPOSE.  See  the +
 + GNU General Public License for more details.                              +
 +                                                                           +
 + You  should  have  received  a  copy  of  the  GNU General Public License +
 + along   with  this  program ;  if  not,  write   to   the  Free  Software +
 + Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA +
 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++/


module room;

import defines;

private import client;
private import messages;
private import server;

class Room
	{
	// static stuff
	private static Room[string]	room_list;
					// room_list[room.name] = room
	private static string[string]	global_room_users;
	
	static ulong nb_rooms ()
		{
		return room_list.length;
		}
	
	static string[] room_names ()
		{
		return room_list.keys;
		}

	static ulong[string] room_stats ()
		{
		ulong[string] stats;

		foreach (Room room ; rooms ())
			{
			stats[room.name] = room.nb_users();
			}

		return stats;
		}
	
	static Room[] rooms ()
		{
		return room_list.values;
		}
	
	static bool find_room (string roomname)
		{
		return (roomname in Room.room_list) ? true : false;
		}
	
	static Room get_room (string roomname)
		{
		if (find_room (roomname))
			{
			return room_list[roomname];
			}
		else
			{
			return null;
			}
		}
	
	static void join_room (string roomname, User user)
		{
		Room room;
		if (!(roomname in Room.room_list))
			{
			room = new Room (roomname, user.server);
			}
		else
			{
			room = room_list[roomname];
			}

		room.join (user);
		}

	static void add_global_room_user (string username)
		{
		if (!(username in global_room_users))
			{
			global_room_users[username] = username;
			}
		}

	static void remove_global_room_user (string username)
		{
		if (username in global_room_users)
			{
			global_room_users.remove (username);
			}
		}

	static string[] get_global_room_users ()
		{
		return global_room_users.keys;
		}

	// constructor
	this (string name, Server serv)
		{
		this.server = serv;
		this.name = name;
		Room.room_list[name] = this;
		}

	
	// misc
	Server server;
	string name;

	void send_to_all (Message m)
		{
		foreach (User user ; this.users ())
			{
			user.send_message (m);
			}
		}

	void say (string username, string message)
		{
		if (this.find_user (username))
			send_to_all (new SSayChatroom (this.name, username, message));
		}
	// users
	private string[string] user_list;	// user_list[username] = username

	ulong nb_users ()
		{
		return user_list.length;
		}
	
	User[string] get_users ()
		{
		User[string] tmp;
		foreach (User user ; this.users ())
			{
			tmp[user.username] = user;
			}
		return tmp;
		}
	
	string[] user_names ()
		{
		return user_list.keys;
		}
	
	uint[string] statuses ()
		{
		uint[string] statuses;

		foreach (User user ; users ())
			{
			statuses[user.username] = user.status;
			}

		return statuses;
		}
	
	uint[string] speeds ()
		{
		uint[string] speeds;

		foreach (User user ; users ())
			{
			speeds[user.username] = user.speed;
			}

		return speeds;
		}
	
	uint[string] upload_numbers ()
		{
		uint[string] upload_numbers;

		foreach (User user ; users ())
			{
			upload_numbers[user.username] = user.upload_number;
			}

		return upload_numbers;
		}
	
	uint[string] somethings ()
		{
		uint[string] somethings;

		foreach (User user ; users ())
			{
			somethings[user.username] = user.something;
			}

		return somethings;
		}
	
	uint[string] shared_files ()
		{
		uint[string] shared_files;

		foreach (User user ; users ())
			{
			shared_files[user.username] = user.shared_files;
			}

		return shared_files;
		}
	
	uint[string] shared_folders ()
		{
		uint[string] shared_folders;

		foreach (User user ; users ())
			{
			shared_folders[user.username] = user.shared_folders;
			}

		return shared_folders;
		}
	
	uint[string] slots_full ()
		{
		uint[string] slots_full;

		foreach (User user ; users ())
			{
			slots_full[user.username] = user.slots_full;
			}

		return slots_full;
		}

	string[string] country_codes ()
		{
		string[string] country_codes;

		foreach (User user ; users ())
			{
			country_codes[user.username] = user.country_code;
			}

		return country_codes;
		}
	
	User[] users ()
		{
		User tmp;
		User[] list;
		foreach (string username ; user_list)
			{
			tmp = server.get_user (username);
			if (tmp !is null) list ~= tmp;
			}
		return list;
		}
	
	bool find_user (User user) {return find_user (user.username);}
	bool find_user (string username)
		{
		return (username in user_list) ? true : false;
		}
	
	void join (User user)
		{
		if (server.find_user (user))
			{
			user_list[user.username] = user.username;

			user.send_message (new SJoinRoom   (this.name, this.user_names (), this.statuses (), this.speeds (), this.upload_numbers (), this.somethings (), this.shared_files (), this.shared_folders (), this.slots_full (), this.country_codes ()));
			user.send_message (new SRoomTicker (this.name, this.tickers));
			user.join_room    (this.name);

			this.send_to_all  (new SUserJoinedRoom (this.name, user.username, user.status, user.speed, user.upload_number, user.something, user.shared_files, user.shared_folders, user.slots_full, user.country_code));
			if (this.nb_users() == 1) server.send_to_all (new SRoomList (Room.room_stats ()));
			}
		}
	
	void leave (User user)
		{
		if (this.find_user (user))
			{
			user_list.remove (user.username);
			this.send_to_all (new SUserLeftRoom (user.username, this.name));
			}
		if (this.nb_users () == 0)
			{
			Room.room_list.remove (this.name);
			}
		}
	
	// tickers
	string[string] ticker_list;	// ticker_list[username] = content

	ulong nb_tickers ()
		{
		return ticker_list.length;
		}
	
	string[string] tickers ()
		{
		return ticker_list;
		}
	
	void add_ticker (string username, string content)
		{
		if (content == "")
			{
			del_ticker (username);
			return;
			}
		ticker_list[username] = content;
		this.send_to_all (new SRoomTickerAdd (this.name, username, content));
		}
	
	void del_ticker (string username)
		{
		if (username in ticker_list)
			{
			ticker_list.remove (username);
			this.send_to_all (new SRoomTickerRemove (this.name, username));
			}
		}
	}
