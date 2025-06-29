<!--
  SPDX-FileCopyrightText: 2025 Soulfind Contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# Windows Import Libraries

Windows requires import libraries (`.lib` files) in order to link against
system DLLs. Import libraries are only shipped with the Windows SDK, which is
huge. To avoid the hassle of downloading the SDK, we generate import libraries
ourselves using `.def` files listing exported functions.

At present, we only use the winsqlite3 system DLL. Whenever you use new sqlite
functions in the code base, you must add them to the `.def` file. GitHub
Actions will then generate the updated import libraries and push them to the
branch.
