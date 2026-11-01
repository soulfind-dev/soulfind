// SPDX-FileCopyrightText: 2025-2026 Soulfind Contributors
// SPDX-License-Identifier: GPL-3.0-or-later


module soulfind.cli;
@safe:

import soulfind.defines : VERSION;
import std.algorithm.mutation : remove;
import std.array : Appender;
import std.compiler : name, version_major, version_minor;
import std.stdio : writeln;
import std.string : startsWith;

enum s_prefix        = "-";
enum l_prefix        = "--";
enum column_spacing  = 2;

struct CommandOption {
    string                  s_parameter;
    string                  l_parameter;
    string                  description;
    string                  choice_name;
    string[]                defaults;
    void delegate(string[]) callback;
}

final class CommandException : Exception
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

void parse_args(string[] args, CommandOption[] options)
{
    size_t i = 1;
    while (i < args.length) {
        string arg = args[i];
        string name;
        string[] values;

        if (arg.startsWith(l_prefix)) {
            foreach (j, ref c; arg) {
                if (c == '=') {
                    name = arg[l_prefix.length .. j];
                    values ~= arg[j + 1 .. $];
                    break;
                }
            }
            if (name is null) name = arg[l_prefix.length .. $];
        }
        else if (arg.startsWith(s_prefix)) {
            name = arg[s_prefix.length .. $];
        }
        else {
            throw new CommandException(
                args[0] ~ ": Unexpected positional argument '" ~ arg ~ "'"
            );
        }

        CommandOption option;
        bool found_option;
        foreach (ref item; options) {
            if ((arg.startsWith(l_prefix) && item.l_parameter == name) ||
                (arg.startsWith(s_prefix) && item.s_parameter == name)) {
                option = item;
                found_option = true;
                break;
            }
        }
        if (!found_option) throw new CommandException(
            args[0] ~ ": Unknown option '" ~ arg ~ "'"
        );

        while (args.length > i + 1
               && !args[i + 1].startsWith(s_prefix)
               && !args[i + 1].startsWith(l_prefix)) {
            values ~= args[i + 1];
            args = args.remove(i + 1);
        }
        if (option.defaults.length == 0) {
            auto max_i = (option.choice_name is null ? 0 : 1);
            if (values.length > max_i) throw new CommandException(
                name ~ ": Unexpected value '" ~ values[max_i] ~ "'"
            );
        }
        if (option.choice_name !is null && values.length == 0) {
            if (option.defaults.length == 0) throw new CommandException(
                name ~ ": Missing value for <" ~ option.choice_name ~ ">"
            );
            values = option.defaults;
        }

        try option.callback(values);
        catch (Exception e) throw new CommandException(name ~ ": " ~ e.msg);

        args = args.remove(i);
    }
}

void print_help(string description, CommandOption[] options)
{
    char[] spacing(size_t num_chars)
    {
        char[] spacing = new char[num_chars];
        spacing[] = ' ';
        return spacing;
    }

    Appender!string output;
    output ~= description;

    size_t s_max;
    size_t l_max;

    foreach (option; options) {
        const s_length = option.s_parameter.length;
        auto l_length = option.l_parameter.length;
        const choice_len = option.choice_name.length;

        if (choice_len > 0)  l_length += choice_len + 3;
        if (s_length > s_max)  s_max = s_length;
        if (l_length > l_max)  l_max = l_length;
    }

    if (s_max > 0)  s_max += column_spacing + s_prefix.length;
    if (l_max > 0)  l_max += column_spacing + l_prefix.length;

    foreach (option; options) {
        output ~= "\n";

        auto s_parameter = option.s_parameter;
        auto l_parameter = option.l_parameter;
        auto choice_name = option.choice_name;

        if (s_parameter.length > 0)  s_parameter = s_prefix ~ s_parameter;
        if (l_parameter.length > 0)  l_parameter = l_prefix ~ l_parameter;
        if (choice_name.length > 0) {
            if (option.defaults.length > 0)
                l_parameter ~= " [" ~ choice_name ~ "]";
            else
                l_parameter ~= " <" ~ choice_name ~ ">";
        }

        output ~= s_parameter;
        output ~= spacing(s_max - s_parameter.length);

        output ~= l_parameter;
        output ~= spacing(l_max - l_parameter.length);

        output ~= option.description;
    }
    writeln(output[]);
}

void print_version()
{
    writeln(
        "Soulfind ", VERSION, " (compiled with ", name, " ", version_major,
        ".", version_minor, ")"
    );
}
