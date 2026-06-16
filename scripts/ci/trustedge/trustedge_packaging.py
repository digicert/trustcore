#!/usr/bin/env python3

import shutil
import zipfile
from pathlib import Path

REPO_ROOT = Path.cwd()
OUTPUT_PACKAGE = REPO_ROOT / "release_package"
ZIP_NAME = REPO_ROOT / "final_package.zip"

FOLDERS_TO_COPY = [
    "bin",
    "bin_static",
    "samples/zephyr_examples",
    "src/crypto",
    "src/crypto_interface",
    "src/platform",
    "src/cap",
    "src/ssl",
    "src/mqtt",
    "src/cert_enroll",
    "src/scep",
    "src/est",
    "src/common",
    "src/harness",
    "src/tap",
    "src/smp",
    "src/asn1",
    "src/http",
    "src/ldap",
    "src/ssh",
    "src/trustedge",
    "scripts/ci/trustedge",
    "projects/trustedge",
    "projects/shared_cmake",
    "projects/common",
    "projects/platform",
    "projects/asn1",
    "projects/initialize",
    "projects/nanocap",
    "projects/crypto",
    "projects/nanocert",
    "projects/cert_enroll",
    "projects/nanossl",
    "projects/mqtt_client",
    "thirdparty/miniz"
]

FILES_TO_COPY = [
    "samples/common/external_rand_thread.c",
    "samples/common/custom_entropy.c",
    "samples/common/custom_entropy.h",
    "samples/mqtt_client/src/mqtt_client_example.c",
    "scripts/check_for_osi.sh",
    "docs/trustedge.1"
]

def copy_folder(src_relative: str):
    src_path = REPO_ROOT / src_relative
    if not src_path.exists():
        print(f"[WARNING] Folder does not exist: {src_path}")
        return

    dest_path = OUTPUT_PACKAGE / src_relative
    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
    print(f"Copied folder: {src_relative}")


def copy_file(src_relative: str):
    src_path = REPO_ROOT / src_relative
    if not src_path.exists():
        print(f"[WARNING] File does not exist: {src_path}")
        return

    dest_path = OUTPUT_PACKAGE / src_relative
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dest_path)
    print(f"Copied file: {src_relative}")


def zip_folder(folder: Path, zip_name: Path, top_level_name: str = "final_package"):
    if zip_name.exists():
        zip_name.unlink()

    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in folder.rglob("*"):
            if file.is_file():
                arcname = Path(top_level_name) / file.relative_to(folder)
                zipf.write(file, arcname)

    print(f"\nCreated ZIP: {zip_name}")

def main():
    print("=== Building Release Package ===")
    if OUTPUT_PACKAGE.exists():
        shutil.rmtree(OUTPUT_PACKAGE)
    OUTPUT_PACKAGE.mkdir(parents=True, exist_ok=True)

    for folder in FOLDERS_TO_COPY:
        copy_folder(folder)

    for file in FILES_TO_COPY:
        copy_file(file)

    zip_folder(OUTPUT_PACKAGE, ZIP_NAME, top_level_name="final_package")

    print("\n=== DONE ===")
    print(f"Anyone who unzips {ZIP_NAME.name} will get:")
    for folder in FOLDERS_TO_COPY:
        print(f"  {folder}")
    for file in FILES_TO_COPY:
        print(f"  {file}")


if __name__ == "__main__":
    main()
