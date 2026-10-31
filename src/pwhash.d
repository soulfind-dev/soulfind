// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.pwhash;
@safe:

import core.atomic : atomicLoad, atomicStore;
import std.algorithm.iteration : splitter;
import std.array : Appender;
import std.bitmanip : nativeToBigEndian;
import std.conv : ConvException, text, to;
import std.digest : LetterCase, secureEqual, toHexString;
import std.digest.hmac : HMAC;
import std.digest.sha : SHA512;
import std.parallelism : Task, task, TaskPool, totalCPUs;
import std.random : unpredictableSeed;
import std.string : split;

private alias HashTask    = Task!(hash_password_task, shared(bool)*, string,
                                  string, uint)*;
private alias VerifyTask  = Task!(verify_password_task, shared(bool)*, string,
                                  string)*;

private HashTask[HashCallback]    hash_password_tasks;
private VerifyTask[HashCallback]  verify_password_tasks;
private TaskPool                  pool;

alias HashCallback  = void delegate(HashResult);
struct HashResult
{
    string  hash;
    string  password;
    bool    matches;
    uint    iterations;
}

shared static this()
{
    pool = new TaskPool(totalCPUs > 1 ? totalCPUs - 1 : 1);
    pool.isDaemon = true;
}

string create_salt()
{
    enum length = 16;
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

string hash_password(string password, string salt, uint iterations)
{
    enum algorithm = "pbkdf2-sha512";
    auto hmac = HMAC!SHA512(cast(immutable(ubyte)[]) password);
    auto digest = hmac
        .put(cast(immutable(ubyte)[]) salt)
        .put(1.nativeToBigEndian)
        .finish();
    auto iter_digest = digest;

    foreach (i; 1 .. iterations) {
        iter_digest = hmac.put(iter_digest).finish();
        foreach (n, ref c; digest) c ^= iter_digest[n];
    }

    // PHC string format
    return text(
        "$", algorithm, "$i=", iterations, "$", salt, "$",
        digest.toHexString!(LetterCase.lower)
    );
}

void hash_password_async(string password, string salt, uint iterations,
                         HashCallback callback)
{
    auto cancel = new shared bool;
    auto task = task!hash_password_task(cancel, password, salt, iterations);
    pool.put(task);
    hash_password_tasks[callback] = task;
}

HashResult verify_password(string hash, string password)
{
    auto result = HashResult(hash, password);
    auto hash_parts = hash.splitter("$");

    if (hash_parts.empty || hash_parts.front.length != 0)
        return result;

    hash_parts.popFront();

    if (hash_parts.empty || hash_parts.front != "pbkdf2-sha512")
        return result;

    hash_parts.popFront();

    if (hash_parts.empty)
        return result;

    foreach (param; hash_parts.front.splitter(",")) {
        const parts = param.split("=");
        if (parts.length != 2)
            continue;

        if (parts[0] == "i")
            try result.iterations = parts[1].to!uint; catch (ConvException) {}
    }
    if (result.iterations == 0)
        return result;

    hash_parts.popFront();

    if (hash_parts.empty)
        return result;

    const salt = hash_parts.front;
    const current_hash = hash_password(password, salt, result.iterations);
    result.matches = secureEqual(current_hash, hash);
    return result;
}

void verify_password_async(string hash, string password, HashCallback callback)
{
    auto cancel = new shared bool;
    auto task = task!verify_password_task(cancel, hash, password);
    pool.put(task);
    verify_password_tasks[callback] = task;
}

void cancel_password_task(HashCallback callback)
{
    if (callback in hash_password_tasks) {
        auto cancel = hash_password_tasks[callback].args[0];
        atomicStore(*cancel, true);
    }

    if (callback in verify_password_tasks) {
        auto cancel = verify_password_tasks[callback].args[0];
        atomicStore(*cancel, true);
    }
}

void process_password_tasks()
{
    Appender!(HashCallback[])  hash_password_tasks_to_remove;
    Appender!(HashCallback[])  verify_password_tasks_to_remove;

    bool finish_task(T)(T task, HashCallback callback) {
        if (!task.done)
            return false;

        const cancel = task.args[0];
        const result = task.yieldForce;

        if (!atomicLoad(*cancel))
            callback(result);

        return true;
    }

    foreach (ref callback, ref task ; hash_password_tasks)
        if (finish_task(task, callback))
            hash_password_tasks_to_remove ~= callback;

    foreach (ref callback, ref task ; verify_password_tasks)
        if (finish_task(task, callback))
            verify_password_tasks_to_remove ~= callback;

    foreach (ref callback ; hash_password_tasks_to_remove)
        hash_password_tasks.remove(callback);

    foreach (ref callback ; verify_password_tasks_to_remove)
        verify_password_tasks.remove(callback);
}


// Threaded Tasks

HashResult hash_password_task(shared(bool)* cancel, string password,
                              string salt, uint iterations)
{
    if (atomicLoad(*cancel))
        return HashResult.init;

    const hash = hash_password(password, salt, iterations);
    return HashResult(hash, password);
}

HashResult verify_password_task(shared(bool)* cancel, string hash,
                                string password)
{
    if (atomicLoad(*cancel))
        return HashResult.init;

    const result = verify_password(hash, password);
    return HashResult(hash, password, result.matches, result.iterations);
}
