// SPDX-FileCopyrightText: 2024-2025 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.tests.pwhash2;
@safe:

import soulfind.pwhash;
import std.algorithm.searching : all;
import std.ascii : isDigit, isHexDigit, isLower;
import std.conv : text;
import std.digest : secureEqual;

/// Short password, fewer iterations
@safe unittest
{
    enum password = "abc123";
    enum invalid_password = password ~ "junk";
    enum salt = "d7679b9a8b6ebe430f6b6fec2b9e0d67";
    enum iterations = 100000;
    enum expected_hash = text(
        "$", "pbkdf2-sha512", "$i=", iterations, "$", salt, "$",
        "a64992f627696932f21f4082c97f520e235ae44fd5d36440df65d6a345aca3bfad3f"
      ~ "ed5c256a1e9fa463aa0462f86b591d532dc5664ef16764258196f1b6ab0e"
    );

    const hash = hash_password(password, salt, iterations);
    const invalid_hash = hash_password(invalid_password, salt, iterations);
    const verify_result = verify_password(hash, password);
    const invalid_verify_result = verify_password(hash, invalid_password);

    assert(secureEqual(hash, expected_hash), "Hashes must match");
    assert(!secureEqual(invalid_hash, expected_hash), "Hashes must not match");

    assert(verify_result.matches, "Password must be valid");
    assert(!invalid_verify_result.matches, "Password must be invalid");

    assert(verify_result.iterations == iterations, "Iterations must match");
    assert(
        invalid_verify_result.iterations == iterations, "Iterations must match"
    );
}

/// Long password, more iterations
@safe unittest
{
    enum password = "long_password_123_@/&%¤(#¤#&/¤&_093402347234298372";
    enum invalid_password = password ~ "junk";
    enum salt = "61e9f5e5607f5cdd95afbf4ae2bcd36d";
    enum iterations = 1000000;
    enum expected_hash = text(
        "$", "pbkdf2-sha512", "$i=", iterations, "$", salt, "$",
        "8e222d416e603f6516101943165445c6f8ba041e464961fb0260069f8baaa9da9876"
      ~ "d04c7af6f9307b2377d3dc3cec8155b06aaf0a0d500919ecc9a0b26e956b"
    );

    const hash = hash_password(password, salt, iterations);
    const invalid_hash = hash_password(invalid_password, salt, iterations);
    const verify_result = verify_password(hash, password);
    const invalid_verify_result = verify_password(hash, invalid_password);

    assert(secureEqual(hash, expected_hash), "Hashes must match");
    assert(!secureEqual(invalid_hash, expected_hash), "Hashes must not match");

    assert(verify_result.matches, "Password must be valid");
    assert(!invalid_verify_result.matches, "Password must be invalid");

    assert(verify_result.iterations == iterations, "Iterations must match");
    assert(
        invalid_verify_result.iterations == iterations, "Iterations must match"
    );
}

/// Salt validity
@safe unittest
{
    const salt = create_salt();

    assert(salt.length == 32, "Invalid salt length");
    assert(
        salt.all!(c => c.isHexDigit && (c.isDigit || c.isLower)),
        "Invalid salt"
    );
}

/// Salt uniqueness
@safe unittest
{
    enum num_salts = 100000;
    uint[string] salts;

    foreach (i; 0 .. num_salts) {
        const salt = create_salt();
        salts[salt] = i;
    }

    assert(salts.length == num_salts, "Duplicate salts found");
}
