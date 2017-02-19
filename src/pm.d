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


module pm;

import defines;

private import core.stdc.time : time;

class PM
	{
	// static
	private static PM[int] pm_list;
	private static int[string] nb_pms;

	static int nb_messages (string user)
		{
		return (user in nb_pms) ? nb_pms[user] : 0;
		}

	static bool find_pm (int id)
		{
		return (id in pm_list) ? true : false;
		}

	static PM get_pm (int id)
		{
		if (find_pm (id))	return pm_list[id];
		else			return null;
		}
	
	static void del_pm (int id)
		{
		if (find_pm (id)) pm_list.remove (id);
		}
	
	static void add_pm (PM pm)
		{
		pm_list[pm.id] = pm;
		}

	static int new_id ()
		{
		int id = cast(int)pm_list.length;
		while (find_pm (id))
			{
			id++;
			}
		return id;
		}
	
	static PM[] get_pms_for (string user)
		{
		PM[] pms;
		if (pm_list.length > 0) foreach (PM pm ; pm_list)
			{
			if (pm.to == user) pms ~= pm;
			}
		return pms;
		}
	
	static int nb_pms_for (string user)
		{
		int i;
		if (pm_list.length > 0) foreach (PM pm ; pm_list)
			{
			if (pm.to == user) i++;
			}
		return i;
		}
	
	// attributes
	int	id;
	int	timestamp;	// in UTC time

	string	from;
	string	to;

	string	content;
	
	// constructor
	this (string content, string from, string to)
		{
		this.id		= PM.new_id ();
		this.from	= from;
		this.to		= to;
		this.content	= content;

		this.timestamp  = cast(int)time(null);
			// timestamp is in seconds since 01/01/1970

		this.nb_pms[to]++;
		}
	}
