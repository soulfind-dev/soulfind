// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.pwhash;
@safe:

import std.algorithm : all, splitter;
import std.ascii : isDigit, isHexDigit, isLower;
import std.bitmanip : nativeToBigEndian;
import std.conv : to;
import std.digest : LetterCase, secureEqual, toHexString;
import std.digest.hmac : HMAC;
import std.digest.sha : SHA512;
import std.exception : ifThrown;
import std.random : unpredictableSeed;
import std.string : format, representation;

string hash_password(string password, string salt, uint iterations)
{
    const algorithm = "pbkdf2_sha512";
    auto hmac = HMAC!SHA512(password.representation);
    auto digest = hmac
        .put(salt.representation)
        .put(1.nativeToBigEndian)
        .finish();
    auto iter_digest = digest;

    foreach (i; 1 .. iterations) {
        iter_digest = hmac.put(iter_digest).finish();
        foreach (n, ref c; digest) c ^= iter_digest[n];
    }

    // Common format found in e.g. Django
    return format!(
        "%s$%d$%s$%s")(
        algorithm, iterations, salt, digest.toHexString!(LetterCase.lower)
    );
}

string create_salt()
{
    const length = 16;
    ubyte[length] salt;
    ubyte offset;

    foreach (_; 0 .. length / uint.sizeof) {
        // unpredictableSeed is cryptographically secure on all operating
        // systems we care about (Linux, macOS, Windows, BSDs) in recent
        // D versions
        salt[offset .. offset + uint.sizeof] = unpredictableSeed
            .nativeToBigEndian;
        offset += uint.sizeof;
    }

    return salt.toHexString!(LetterCase.lower).idup;
}

bool verify_password(string hash, string password)
{
    auto hash_parts = hash.splitter("$");

    if (hash_parts.empty)
        return false;

    hash_parts.popFront();

    if (hash_parts.empty)
        return false;

    const iterations = hash_parts.front.to!uint.ifThrown(0);
    hash_parts.popFront();

    if (hash_parts.empty)
        return false;

    const salt = hash_parts.front;
    const current_hash = hash_password(password, salt, iterations);

    return secureEqual(current_hash, hash);
}
