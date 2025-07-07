#!/usr/bin/env python3

import argparse
import requests
import os
import json
import csv
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
import secrets
import traceback

CONFIG_PATH = Path.home() / ".linux.sh_meta.csv"
DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

BASE_URL = "https://linux.sh/"
TOR_URL = "http://7b42twezybs23hrr.onion/"

now = datetime.now()

def load_file_list():
    entries = []
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open('r') as f:
            reader = csv.reader(f)
            for row in reader:
                entries.append(row)
    return entries

def save_file_list(entries):
    with CONFIG_PATH.open('w') as f:
        writer = csv.writer(f)
        for entry in entries:
            writer.writerow(entry)

def cleanup_file_list(entries):
    cleaned = []
    for row in entries:
        expires = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
        if now > expires:
            print(f"File expired: {row[1]}")
        else:
            cleaned.append(row)
    return cleaned

def derive_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=DEFAULT_SCRYPT_N, r=DEFAULT_SCRYPT_R, p=DEFAULT_SCRYPT_P, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(in_path, out_path, password):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    with open(in_path, 'rb') as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    with open(out_path, 'wb') as f:
        f.write(salt + nonce + ct)

def decrypt_content(content, password):
    salt = content[:16]
    nonce = content[16:28]
    ct = content[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def upload_file(file_path, proxies=None):
    with open(file_path, 'rb') as f:
        response = requests.post(BASE_URL + 'upload.php', files={'file': f}, proxies=proxies)
    if response.status_code != 200:
        raise Exception("Upload failed")
    return json.loads(response.content)

parser = argparse.ArgumentParser()
parser.add_argument("--upload")
parser.add_argument("--encrypt", action="store_true")
parser.add_argument("--ls", action="store_true")
parser.add_argument("--cleanup", action="store_true")
parser.add_argument("--download")
parser.add_argument("--rm")
parser.add_argument("--tor", action="store_true")
args = parser.parse_args()

entries = load_file_list()
entries = cleanup_file_list(entries)

try:
    if args.ls:
        print("Currently uploaded files:")
        for row in entries:
            print(f"Filename: {row[0]}, Upload: {row[1]}, Expires: {row[2]}")

    if args.upload:
        ufile = Path(args.upload)
        encrypted_flag = "0"
        final_path = ufile

        if args.encrypt:
            password = getpass.getpass("Password: ")
            enc_path = ufile.with_suffix(ufile.suffix + ".enc")
            encrypt_file(ufile, enc_path, password)
            final_path = enc_path
            encrypted_flag = "1"

        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"} if args.tor else None
        meta = upload_file(final_path, proxies=proxies)

        print("Upload complete")
        print(f"Original Filename: {meta['filename']['OriginalFileName']}")
        print(f"Uploaded Filename: {meta['filename']['UploadFilename']}")
        print(f"File Expires: {meta['filename']['UploadExpires']}")
        print(f"File Hash: {meta['filename']['UploadHash']}")
        print(f"File Hash After Upload: {meta['filename']['UploadHashAfterEncryption']}")

        entries.append([
            meta['filename']['OriginalFileName'],
            meta['filename']['UploadFilename'],
            meta['filename']['UploadExpires'],
            meta['filename']['UploadControlKey'],
            encrypted_flag
        ])

        if final_path != ufile:
            final_path.unlink()

    if args.cleanup:
        print("Cleanup complete.")

    if args.download:
        found = next((row for row in entries if row[1] == args.download), None)
        if found:
            password = None
            if found[4] == "1":
                password = getpass.getpass("Password: ")
            proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"} if args.tor else None
            r = requests.post(BASE_URL + 'download.php', data={'filename': found[1], 'control': found[3]}, proxies=proxies)
            data = r.content
            if password:
                data = decrypt_content(data, password)
            with open(found[0], 'wb') as f:
                f.write(data)
            print(f"Downloaded and saved as {found[0]}")
        else:
            print("File not found in local metadata.")

    if args.rm:
        entries = [row for row in entries if row[1] != args.rm]
        print("Removed entry from local metadata.")

finally:
    save_file_list(entries)

