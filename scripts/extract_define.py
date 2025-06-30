import json
import re
import sys
from pathlib import Path

def get_most_child_dir(path):
    return Path(path).name

def extract_macros(json_path, server_file, client_file):
    with open(json_path, 'r') as f:
        compile_commands = json.load(f)

    client_macros = set()
    server_macros = set()
    for entry in compile_commands:
        command = entry.get('command', '')
        arguments = entry.get('arguments', [])
        directory = entry.get('directory', '')

        dir_name = get_most_child_dir(directory)

        # Extract macros from 'command' string
        if dir_name == 'ssh_client':
            client_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    client_macros.add(arg[2:])
        elif dir_name == 'ssh_server':
            server_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    server_macros.add(arg[2:])
        else:
            client_macros.update(re.findall(r'-D(\w+)', command))
            server_macros.update(re.findall(r'-D(\w+)', command))

            # Extract macros from 'arguments' list
            for arg in arguments:
                if arg.startswith('-D'):
                    client_macros.add(arg[2:])
                    server_macros.add(arg[2:])

    with open(server_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(server_macros):
            f.write(f"#ifndef {macro}\n")
            f.write(f"#define {macro}\n")
            f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {server_file} generated successfully.")

    with open(client_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(client_macros):
            f.write(f"#ifndef {macro}\n")
            f.write(f"#define {macro}\n")
            f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {client_file} generated successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python extract_define.py <path_to_compile_commands.json>")
        sys.exit(1)

    json_path = sys.argv[1]
    server_macros = sys.argv[2]
    client_macros = sys.argv[3]
    extract_macros(json_path, server_macros, client_macros)
