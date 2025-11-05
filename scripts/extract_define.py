import json
import re
import sys
from pathlib import Path

def get_most_child_dir(path):
    return Path(path).name

def extract_macros(json_path, ssh_server_file, ssh_client_file, mqtt_client_file):
    with open(json_path, 'r') as f:
        compile_commands = json.load(f)

    ssh_client_macros = set()
    ssh_server_macros = set()
    mqtt_client_macros = set()
    for entry in compile_commands:
        command = entry.get('command', '')
        arguments = entry.get('arguments', [])
        directory = entry.get('directory', '')

        dir_name = get_most_child_dir(directory)

        # Extract macros from 'command' string
        if dir_name == 'ssh_client':
            ssh_client_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    ssh_client_macros.add(arg[2:])
        elif dir_name == 'ssh_server':
            ssh_server_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    ssh_server_macros.add(arg[2:])
        elif dir_name == 'mqtt_client':
            mqtt_client_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    mqtt_client_macros.add(arg[2:])
        else:
            ssh_client_macros.update(re.findall(r'-D(\w+)', command))
            ssh_server_macros.update(re.findall(r'-D(\w+)', command))
            mqtt_client_macros.update(re.findall(r'-D(\w+)', command))

            # Extract macros from 'arguments' list
            for arg in arguments:
                if arg.startswith('-D'):
                    ssh_client_macros.add(arg[2:])
                    ssh_server_macros.add(arg[2:])
                    mqtt_client_macros.add(arg[2:])

    with open(ssh_server_file, 'w') as f:
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

        for macro in sorted(ssh_server_macros):
            if "__ENABLE_MOCANA_SSH_CLIENT__" != macro:
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssh_server_file} generated successfully.")

    with open(ssh_client_file, 'w') as f:
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

        for macro in sorted(ssh_client_macros):
            if "__ENABLE_MOCANA_SSH_SERVER__" != macro:
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssh_client_file} generated successfully.")

    with open(mqtt_client_file, 'w') as f:
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

        for macro in sorted(mqtt_client_macros):
            f.write(f"#ifndef {macro}\n")
            f.write(f"#define {macro}\n")
            f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {mqtt_client_file} generated successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python extract_define.py <path_to_compile_commands.json> <ssh_server_file> <ssh_client_file> <mqtt_client_file>")
        sys.exit(1)

    json_path = sys.argv[1]
    ssh_server_macros = sys.argv[2]
    ssh_client_macros = sys.argv[3]
    mqtt_client_macros = sys.argv[4]
    extract_macros(json_path, ssh_server_macros, ssh_client_macros, mqtt_client_macros)
