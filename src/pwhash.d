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

private struct HashTask
{
    Task!(hash_password_task, string, string, uint, shared(bool)*)*  task;
    shared(bool)*                                                    cancel;
}

private struct VerifyTask
{
    Task!(verify_password_task, string, string, shared(bool)*)*      task;
    shared(bool)*                                                    cancel;
}

private alias HashCallback    = void delegate(string, string);
private alias VerifyCallback  = void delegate(string, bool, uint);

private HashTask[HashCallback]      hash_password_tasks;
private VerifyTask[VerifyCallback]  verify_password_tasks;
private TaskPool                    pool;

struct VerifyPasswordResult
{
    bool  matches;
    uint  iterations;
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
    auto task = task!hash_password_task(password, salt, iterations, cancel);
    pool.put(task);
    hash_password_tasks[callback] = HashTask(task, cancel);
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
    auto cancel = new shared bool;
    auto task = task!verify_password_task(hash, password, cancel);
    pool.put(task);
    verify_password_tasks[callback] = VerifyTask(task, cancel);
}

void process_password_tasks()
{
    Appender!(HashCallback[])    hash_password_tasks_to_remove;
    Appender!(VerifyCallback[])  verify_password_tasks_to_remove;

    foreach (ref callback, ref queued ; hash_password_tasks) {
        if (!queued.task.done)
            continue;

        auto result = queued.task.yieldForce;
        hash_password_tasks_to_remove ~= callback;

        if (atomicLoad(*queued.cancel))
            continue;

        callback(result.password, result.hash);
    }
    foreach (ref callback ; hash_password_tasks_to_remove)
        hash_password_tasks.remove(callback);

    foreach (ref callback, ref queued ; verify_password_tasks) {
        if (!queued.task.done)
            continue;

        auto result = queued.task.yieldForce;
        verify_password_tasks_to_remove ~= callback;

        if (atomicLoad(*queued.cancel))
            continue;

        callback(result.password, result.matches, result.iterations);
    }
    foreach (ref callback ; verify_password_tasks_to_remove)
        verify_password_tasks.remove(callback);
}

void cancel_password_task(HashCallback callback)
{
    auto queued_task = callback in hash_password_tasks;
    if (queued_task is null)
        return;

    atomicStore(*queued_task.cancel, true);
}

void cancel_password_task(VerifyCallback callback)
{
    auto queued_task = callback in verify_password_tasks;
    if (queued_task is null)
        return;

    atomicStore(*queued_task.cancel, true);
}


// Threaded Tasks

private struct TaskResult
{
    string  hash;
    string  password;
    bool    matches;
    uint    iterations;
}

TaskResult hash_password_task(string password, string salt, uint iterations,
                              shared(bool)* cancel)
{
    if (atomicLoad(*cancel))
        return TaskResult();  // Registration cancelled after timeout

    const hash = hash_password(password, salt, iterations);
    return TaskResult(hash, password);
}

TaskResult verify_password_task(string hash, string password,
                                shared(bool)* cancel)
{
    if (atomicLoad(*cancel))
        return TaskResult();  // Login cancelled after timeout

    const result = verify_password(hash, password);
    return TaskResult(hash, password, result.matches, result.iterations);
}
