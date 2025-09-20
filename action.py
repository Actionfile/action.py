#!/usr/bin/env python3
import argparse
import sys
import os
import re
import subprocess
from configparser import ConfigParser

ACTIONFILE_CANDIDATES = [
    "Actionfile.md", "Actionfile", "ACTIONFILE.md", "actionfile.md"
]

def find_actionfile(path_or_dot):
    if path_or_dot == ".":
        for fname in ACTIONFILE_CANDIDATES:
            if os.path.isfile(fname):
                return fname
        sys.exit("No Actionfile found in current directory.")
    elif os.path.isfile(path_or_dot):
        return path_or_dot
    else:
        sys.exit(f"Actionfile '{path_or_dot}' not found.")

def normalize(s):
    return re.sub(r"[^a-zA-Z0-9]", "", s or "").lower()

def parse_config_vars(lines):
    config_vars = {}
    in_config = False
    in_ini_block = False
    ini_lines = []
    for line in lines:
        if re.match(r"^###\s*config", line, re.I):
            in_config = True
        elif in_config and re.match(r"^```ini", line):
            in_ini_block = True
        elif in_ini_block and re.match(r"^```", line):
            in_ini_block = False
            in_config = False
        elif in_ini_block:
            ini_lines.append(line)
    cp = ConfigParser()
    cp.optionxform = str  # preserve case
    if ini_lines:
        cp.read_string("".join(ini_lines))
        for section in cp.sections():
            section_prefix = section.upper().replace("-", "_")
            for key, value in cp.items(section):
                key_upper = key.upper().replace("-", "_")
                val = value.strip('"').strip("'")
                env_name = f"{section_prefix}_{key_upper}"
                config_vars[env_name] = val
    return config_vars

def parse_vars_block(lines):
    in_vars = False
    in_sh_block = False
    var_lines = []
    for line in lines:
        if re.match(r"^###\s*vars", line, re.I):
            in_vars = True
        elif in_vars and re.match(r"^```sh", line):
            in_sh_block = True
        elif in_sh_block and re.match(r"^```", line):
            in_sh_block = False
            in_vars = False
        elif in_sh_block:
            var_lines.append(line.rstrip())
    return "\n".join(var_lines)

def parse_actionfile(path):
    with open(path, encoding="utf-8") as f:
        lines = list(f)

    actions = []  # list of (name, kind, script)
    current_names = []
    current_kind = None  # "backtick", "context", "action"
    in_sh_code = False
    buffer = []

    header_re = re.compile(r"^###\s+(?:.*`([^`]+)`.*|([a-zA-Z0-9_.\- ]+))")

    for line in lines:
        match = header_re.match(line)
        codeblock_start = re.match(r"^```sh\s*$", line)
        codeblock_end = re.match(r"^```", line)
        if match:
            if current_names and buffer:
                for name in current_names:
                    actions.append((name, current_kind, "\n".join(buffer).rstrip()))
                buffer = []
            if match.group(1):  # backtick
                current_names = [match.group(1).strip()]
                current_kind = "backtick"
            else:
                names = [n.strip() for n in match.group(2).split()]
                current_names = names
                current_kind = "context" if len(names) > 1 else "action"
            in_sh_code = False
            continue
        if codeblock_start and current_names:
            in_sh_code = True
            continue
        if codeblock_end and in_sh_code:
            in_sh_code = False
            continue
        if in_sh_code and current_names:
            buffer.append(line.rstrip())
    if current_names and buffer:
        for name in current_names:
            actions.append((name, current_kind, "\n".join(buffer).rstrip()))
    return actions, lines

def list_actions(actions):
    seen = set()
    for name, _, _ in actions:
        if name not in seen:
            print(name)
            seen.add(name)

def resolve_action(actions, query):
    norm_query = normalize(" ".join(query))
    # 1. Backtick actions first
    for name, kind, script in actions:
        if kind == "backtick" and normalize(name) == norm_query:
            return script
    # 2. Context-action (multi-name headers)
    for name, kind, script in actions:
        if kind == "context" and normalize(name) == norm_query:
            return script
    # 3. Single actions
    for name, kind, script in actions:
        if kind == "action" and normalize(name) == norm_query:
            return script
    # 4. Default (if nothing matched, and no query was given)
    if not query:
        for name, _, script in actions:
            if normalize(name) == "default":
                return script
    return None

def parse_env_args(argv):
    extra_env = {}
    cleaned = []
    i = 0
    while i < len(argv):
        if argv[i] == "--arg" and i+1 < len(argv):
            k, v = argv[i+1].split("=", 1)
            extra_env[k] = v
            i += 2
        elif argv[i].startswith("--arg="):
            k, v = argv[i][6:].split("=", 1)
            extra_env[k] = v
            i += 1
        else:
            cleaned.append(argv[i])
            i += 1
    return cleaned, extra_env

def main():
    parser = argparse.ArgumentParser(description="Actionfile executor")
    parser.add_argument("file", help="Actionfile to use, or '.' to search in current dir")
    parser.add_argument("action", nargs="*", help="Action to run (can be multiple words)")
    parser.add_argument("--shell", "-s", help="Shell to use (default: $SHELL or bash)")
    parser.add_argument("--list-actions", action="store_true", help="List available actions")
    parser.add_argument("--arg", action="append", default=[], help="Set environment variable (can be repeated, format VAR=VAL)")

    args = parser.parse_args()

    if args.list_actions:
        actions, _ = parse_actionfile(find_actionfile(args.file))
        list_actions(actions)
        sys.exit(0)

    extra_env = {}
    for argstr in args.arg:
        if "=" in argstr:
            k, v = argstr.split("=", 1)
            extra_env[k] = v

    actions, lines = parse_actionfile(find_actionfile(args.file))
    config_env = parse_config_vars(lines)
    vars_block = parse_vars_block(lines)
    script = resolve_action(actions, args.action)
    if not script:
        sys.exit(f"No action found for '{' '.join(args.action)}'")

    full_script = ""
    if vars_block:
        full_script += vars_block + "\n"
    if config_env:
        for k, v in config_env.items():
            full_script += f'{k}="{v}"\n'
    if extra_env:
        for k, v in extra_env.items():
            full_script += f'export {k}="{v}"\n'
    full_script += script

    # Prefer command-line shell, then $SHELL, then bash
    shell = args.shell or os.environ.get("SHELL", "bash")
    cmd = [shell, "-l", "-c", full_script, "--"]
    sys.exit(subprocess.call(cmd, env={**os.environ, **extra_env}))

if __name__ == "__main__":
    main()
