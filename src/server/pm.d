// SPDX-FileCopyrightText: 2024 Soulfind Contributors
// SPDX-FileCopyrightText: 2005-2017 SeeSchloss <seeschloss@seeschloss.org>
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.server.pm;
@safe:

struct PM
{
    uint    id;
    ulong   timestamp;
    string  from;
    string  to;
    string  content;
}
