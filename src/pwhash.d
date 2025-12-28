// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.pwhash;
@safe:

import std.algorithm.iteration : splitter;
import std.array : Appender;
import std.bitmanip : nativeToBigEndian;
import std.conv : ConvException, text, to;
import std.digest : LetterCase, secureEqual, toHexString;
import std.digest.hmac : HMAC;
import std.digest.sha : SHA512;
import std.parallelism : Task, task, taskPool;
import std.random : unpredictableSeed;
import std.string : split;

private alias HashTask    = Task!(hash_password_task, string, string, uint)*;
private alias VerifyTask  = Task!(verify_password_task, string, string)*;

private alias HashCallback    = void delegate(string, string);
private alias VerifyCallback  = void delegate(string, bool, uint);

private HashTask[HashCallback]      hash_password_tasks;
private VerifyTask[VerifyCallback]  verify_password_tasks;

struct VerifyPasswordResult
{
    bool  matches;
    uint  iterations;
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
    auto task = task!hash_password_task(password, salt, iterations);
    taskPool.put(task);
    hash_password_tasks[callback] = task;
}

VerifyPasswordResult verify_password(string hash, string password)
{
    auto result = VerifyPasswordResult();
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

void verify_password_async(string hash, string password,
                           VerifyCallback callback)
{
    auto task = task!verify_password_task(hash, password);
    taskPool.put(task);
    verify_password_tasks[callback] = task;
}

void process_password_tasks()
{
    Appender!(HashCallback[])    hash_password_tasks_to_remove;
    Appender!(VerifyCallback[])  verify_password_tasks_to_remove;

    foreach (ref callback, ref task ; hash_password_tasks) {
        if (!task.done)
            continue;

        auto result = task.yieldForce;
        callback(result.password, result.hash);
        hash_password_tasks_to_remove ~= callback;
    }
    foreach (ref callback ; hash_password_tasks_to_remove)
        hash_password_tasks.remove(callback);

    foreach (ref callback, ref task ; verify_password_tasks) {
        if (!task.done)
            continue;

        auto result = task.yieldForce;
        callback(result.password, result.matches, result.iterations);
        verify_password_tasks_to_remove ~= callback;
    }
    foreach (ref callback ; verify_password_tasks_to_remove)
        verify_password_tasks.remove(callback);
}


// Threaded Tasks

private struct TaskResult
{
    string  hash;
    string  password;
    bool    matches;
    uint    iterations;
}

TaskResult hash_password_task(string password, string salt, uint iterations)
{
    const hash = hash_password(password, salt, iterations);
    return TaskResult(hash, password);
}

TaskResult verify_password_task(string hash, string password)
{
    const result = verify_password(hash, password);
    return TaskResult(hash, password, result.matches, result.iterations);
}
