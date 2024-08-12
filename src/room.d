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
@safe:

import defines;

private import client;
private import messages;
private import server;

class Room
	{
	// static stuff
	private static Room[string]	room_list;
					// room_list[room.name] = room
	private static string[string]	global_room_user_list;

	static void join_room (string roomname, User user)
		{
		auto room = get_room (roomname);
		if (!room) room = new Room (roomname);
		room.add_user (user);
		}

	static Room get_room (string roomname)
		{
		if (roomname !in room_list) return null;
		return room_list[roomname];
		}

	static Room[] rooms ()
		{
		return room_list.values;
		}

	static ulong[string] room_stats ()
		{
		ulong[string] stats;
		foreach (room ; rooms) stats[room.name] = room.nb_users;
		return stats;
		}

	static void add_global_room_user (string username)
		{
		if (username in global_room_user_list) return;
		global_room_user_list[username] = username;
		}

	static void remove_global_room_user (string username)
		{
		if (username !in global_room_user_list) return;
		global_room_user_list.remove (username);
		}

	static string[] global_room_users ()
		{
		return global_room_user_list.keys;
		}

	string name;

	// constructor
	this (string name)
		{
		this.name = name;
		room_list[name] = this;
		}

	// misc
	void send_to_all (Message msg)
		{
		foreach (User user ; users) user.send_message (msg);
		}

	void say (string username, string message)
		{
		if (username !in user_list) return;
		send_to_all (new SSayChatroom (name, username, message));
		}

	// users
	private User[string] user_list;	// user_list[username] = user

	void leave (User user)
		{
		if (user.username !in user_list) return;
		user_list.remove (user.username);
		user.leave_room (this);
		send_to_all (new SUserLeftRoom (user.username, name));

		if (nb_users == 0) room_list.remove (name);
		}

	private void add_user (User user)
		{
		if (user.username in user_list) return;
		user_list[user.username] = user;

		send_to_all (
			new SUserJoinedRoom (
				name, user.username, user.status,
				user.speed, user.upload_number, user.something,
				user.shared_files, user.shared_folders,
				user.slots_full, user.country_code
			)
		);

		user.send_message (
			new SJoinRoom (
				name, user_names, statuses, speeds,
				upload_numbers, somethings, shared_files,
				shared_folders, slots_full, country_codes
			)
		);
		user.send_message (new SRoomTicker (name, tickers));
		user.join_room (this);
		}

	ulong nb_users ()
		{
		return user_list.length;
		}

	User[] users ()
		{
		return user_list.values;
		}

	private string[] user_names ()
		{
		return user_list.keys;
		}

	private uint[string] statuses ()
		{
		uint[string] statuses;

		foreach (User user ; users ())
			{
			statuses[user.username] = user.status;
			}

		return statuses;
		}

	private uint[string] speeds ()
		{
		uint[string] speeds;

		foreach (User user ; users ())
			speeds[user.username] = user.speed;

		return speeds;
		}

	private uint[string] upload_numbers ()
		{
		uint[string] upload_numbers;

		foreach (User user ; users ())
			upload_numbers[user.username] = user.upload_number;

		return upload_numbers;
		}
	
	private uint[string] somethings ()
		{
		uint[string] somethings;

		foreach (User user ; users ())
			somethings[user.username] = user.something;

		return somethings;
		}
	
	private uint[string] shared_files ()
		{
		uint[string] shared_files;

		foreach (User user ; users ())
			shared_files[user.username] = user.shared_files;

		return shared_files;
		}
	
	private uint[string] shared_folders ()
		{
		uint[string] shared_folders;

		foreach (User user ; users ())
			shared_folders[user.username] = user.shared_folders;

		return shared_folders;
		}
	
	private uint[string] slots_full ()
		{
		uint[string] slots_full;

		foreach (User user ; users ())
			slots_full[user.username] = user.slots_full;

		return slots_full;
		}

	private string[string] country_codes ()
		{
		string[string] country_codes;

		foreach (User user ; users ())
			country_codes[user.username] = user.country_code;

		return country_codes;
		}
	
	// tickers
	private string[string] tickers;	// tickers[username] = content
	
	void add_ticker (string username, string content)
		{
		if (!content)
			{
			del_ticker (username);
			return;
			}
		tickers[username] = content;
		send_to_all (new SRoomTickerAdd (name, username, content));
		}
	
	private void del_ticker (string username)
		{
		if (username !in tickers) return;
		tickers.remove (username);
		send_to_all (new SRoomTickerRemove (name, username));
		}
	}
