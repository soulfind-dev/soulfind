// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-FileCopyrightText: 2024 Mat (mathiascode)
// SPDX-License-Identifier: GPL-3.0-or-later


module room;
@safe:

import defines;

import client;
import messages;

class Room
	{
	// static stuff
	private static Room[string]		room_list;
	private static string[string]	global_room_user_list;

	static void join_room(string roomname, User user)
	{
		auto room = get_room(roomname);
		if (!room) room = new Room(roomname);
		room.add_user(user);
	}

	static Room get_room(string roomname)
	{
		if (roomname !in room_list)
			return null;

		return room_list[roomname];
	}

	@trusted  // .values doesn't work with @safe in old D versions
	static Room[] rooms()
	{
		return room_list.values;
	}

	static ulong[string] room_stats()
	{
		ulong[string] stats;
		foreach (room ; rooms) stats[room.name] = room.nb_users;
		return stats;
	}

	static void add_global_room_user(string username)
	{
		if (username !in global_room_user_list)
			global_room_user_list[username] = username;
	}

	static void remove_global_room_user(string username)
	{
		if (username in global_room_user_list)
			global_room_user_list.remove(username);
	}

	@trusted  // .keys doesn't work with @safe in old D versions
	static string[] global_room_users()
	{
		return global_room_user_list.keys;
	}

	string name;

	// constructor
	this(string name)
	{
		this.name = name;
		room_list[name] = this;
	}

	// misc
	void send_to_all(Message msg)
	{
		foreach (User user ; users) user.send_message(msg);
	}

	void say(string username, string message)
	{
		if (username in user_list)
			send_to_all(new SSayChatroom(name, username, message));
	}

	// users
	private User[string] user_list;	// user_list[username] = user

	void leave(User user)
	{
		if (user.username !in user_list)
			return;

		user_list.remove(user.username);
		user.leave_room(this);
		send_to_all(new SUserLeftRoom(user.username, name));

		if (nb_users == 0) room_list.remove(name);
	}

	private void add_user(User user)
	{
		if (user.username in user_list)
			return;

		user_list[user.username] = user;

		send_to_all(
			new SUserJoinedRoom(
				name, user.username, user.status,
				user.speed, user.upload_number, user.something,
				user.shared_files, user.shared_folders,
				user.slots_full, user.country_code
			)
		);
		user.send_message(
			new SJoinRoom(
				name, user_names, statuses, speeds,
				upload_numbers, somethings, shared_files,
				shared_folders, slots_full, country_codes
			)
		);
		user.send_message(new SRoomTicker(name, tickers));
		user.join_room(this);
	}

	ulong nb_users()
	{
		return user_list.length;
	}

	@trusted  // .values doesn't work with @safe in old D versions
	User[] users()
	{
		return user_list.values;
	}

	@trusted  // .keys doesn't work with @safe in old D versions
	private string[] user_names()
	{
		return user_list.keys;
	}

	private uint[string] statuses()
	{
		uint[string] statuses;
		foreach (User user ; users)
			statuses[user.username] = user.status;

		return statuses;
	}

	private uint[string] speeds()
	{
		uint[string] speeds;
		foreach (User user ; users)
			speeds[user.username] = user.speed;

		return speeds;
	}

	private uint[string] upload_numbers()
	{
		uint[string] upload_numbers;
		foreach (User user ; users)
			upload_numbers[user.username] = user.upload_number;

		return upload_numbers;
	}
	
	private uint[string] somethings()
	{
		uint[string] somethings;
		foreach (User user ; users)
			somethings[user.username] = user.something;

		return somethings;
	}
	
	private uint[string] shared_files()
	{
		uint[string] shared_files;
		foreach (User user ; users)
			shared_files[user.username] = user.shared_files;

		return shared_files;
	}
	
	private uint[string] shared_folders()
	{
		uint[string] shared_folders;
		foreach (User user ; users)
			shared_folders[user.username] = user.shared_folders;

		return shared_folders;
	}
	
	private uint[string] slots_full()
	{
		uint[string] slots_full;
		foreach (User user ; users)
			slots_full[user.username] = user.slots_full;

		return slots_full;
	}

	private string[string] country_codes()
	{
		string[string] country_codes;
		foreach (User user ; users)
			country_codes[user.username] = user.country_code;

		return country_codes;
	}
	
	// tickers
	private string[string] tickers;	// tickers[username] = content
	
	void add_ticker(string username, string content)
	{
		if (!content) {
			del_ticker(username);
			return;
		}
		tickers[username] = content;
		send_to_all(new SRoomTickerAdd(name, username, content));
	}
	
	private void del_ticker(string username)
	{
		if (username !in tickers)
			return;

		tickers.remove(username);
		send_to_all(new SRoomTickerRemove(name, username));
	}
}
