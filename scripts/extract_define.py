import json
import re
import sys
from pathlib import Path

def get_most_child_dir(path):
    return Path(path).name

def extract_macros(json_path, ci_example_file, ssh_server_file, ssh_client_file, mqtt_client_file, ssl_server_file, ssl_client_file):
    with open(json_path, 'r') as f:
        compile_commands = json.load(f)

    # Macros to filter out from generated header files
    exclude_macros = {
        '__ENABLE_DIGICERT_ESTC__',
        '__ENABLE_DIGICERT_SCEPC__'
    }

    ci_example_macros = set()
    ssh_client_macros = set()
    ssh_server_macros = set()
    mqtt_client_macros = set()
    ssl_macros = set()
    for entry in compile_commands:
        command = entry.get('command', '')
        arguments = entry.get('arguments', [])
        directory = entry.get('directory', '')

        dir_name = get_most_child_dir(directory)

        # Extract macros from 'command' string
        if dir_name == 'crypto_interface_example':
            ci_example_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    ci_example_macros.add(arg[2:])
        elif dir_name == 'ssh_client':
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
        elif dir_name == 'nanossl' or dir_name == 'ssl_client' or dir_name == 'ssl_server':
            ssl_macros.update(re.findall(r'-D(\w+)', command))
            for arg in arguments:
                if arg.startswith('-D'):
                    ssl_macros.add(arg[2:])
        else:
            ci_example_macros.update(re.findall(r'-D(\w+)', command))
            ssh_client_macros.update(re.findall(r'-D(\w+)', command))
            ssh_server_macros.update(re.findall(r'-D(\w+)', command))
            mqtt_client_macros.update(re.findall(r'-D(\w+)', command))
            ssl_macros.update(re.findall(r'-D(\w+)', command))

            # Extract macros from 'arguments' list
            for arg in arguments:
                if arg.startswith('-D'):
                    ci_example_macros.add(arg[2:])
                    ssh_client_macros.add(arg[2:])
                    ssh_server_macros.add(arg[2:])
                    mqtt_client_macros.add(arg[2:])
                    ssl_macros.add(arg[2:])

    with open(ci_example_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_CI_EXAMPLE_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_CI_EXAMPLE_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(ci_example_macros):
            f.write(f"#ifndef {macro}\n")
            f.write(f"#define {macro}\n")
            f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_CI_EXAMPLE_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ci_example_file} generated successfully.")

    with open(ssh_server_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_SSH_SERVER_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_SSH_SERVER_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(ssh_server_macros):
            if macro not in exclude_macros and macro != "__ENABLE_DIGICERT_SSH_CLIENT__":
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_SSH_SERVER_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssh_server_file} generated successfully.")

    with open(ssh_client_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_SSH_CLIENT_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_SSH_CLIENT_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(ssh_client_macros):
            if macro not in exclude_macros and macro != "__ENABLE_DIGICERT_SSH_SERVER__":
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_SSH_CLIENT_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssh_client_file} generated successfully.")

    with open(mqtt_client_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_MQTT_CLIENT_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_MQTT_CLIENT_HEADER__\n")
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
        f.write("#endif /* __MOPTIONS_CUSTOM_MQTT_CLIENT_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {mqtt_client_file} generated successfully.")

    with open(ssl_server_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_SSL_SERVER_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_SSL_SERVER_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(ssl_macros):
            if macro not in exclude_macros and "__ENABLE_DIGICERT_SSL_CLIENT__" != macro and "__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE__" != macro:
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_SSL_SERVER_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssl_server_file} generated successfully.")

    with open(ssl_client_file, 'w') as f:
        f.write("/* Auto-generated header file with build macros */\n")
        f.write("#ifndef __MOPTIONS_CUSTOM_SSL_CLIENT_HEADER__\n")
        f.write("#define __MOPTIONS_CUSTOM_SSL_CLIENT_HEADER__\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("extern \"C\" {\n")
        f.write("#endif\n")

        f.write("\n")
        f.write("/*------------------------------------------------------------------*/\n")
        f.write("\n")

        for macro in sorted(ssl_macros):
            if macro not in exclude_macros and "__ENABLE_DIGICERT_SSL_SERVER__" != macro and "__ENABLE_DIGICERT_SSL_SERVER_EXAMPLE__" != macro:
                f.write(f"#ifndef {macro}\n")
                f.write(f"#define {macro}\n")
                f.write("#endif\n")
        f.write("\n")
        f.write("#ifdef __cplusplus\n")
        f.write("}\n")
        f.write("#endif\n")
        f.write("#endif /* __MOPTIONS_CUSTOM_SSL_CLIENT_HEADER__ */\n")
        f.write("\n")

    print(f"✅ {ssl_client_file} generated successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Usage: python extract_define.py <path_to_compile_commands.json> <ci_example_file> <ssh_server_file> <ssh_client_file> <mqtt_client_file> <ssl_server_file> <ssl_client_file>")
        sys.exit(1)

    json_path = sys.argv[1]
    ci_example_macros = sys.argv[2]
    ssh_server_macros = sys.argv[3]
    ssh_client_macros = sys.argv[4]
    mqtt_client_macros = sys.argv[5]
    ssl_server_macros = sys.argv[6]
    ssl_client_macros = sys.argv[7]
    extract_macros(json_path, ci_example_macros, ssh_server_macros, ssh_client_macros, mqtt_client_macros, ssl_server_macros, ssl_client_macros)
