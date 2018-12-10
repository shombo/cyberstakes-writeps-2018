#!/usr/bin/env python3

import binascii
import hashlib
import sys

with open('flag', 'r') as flagfile:
    FLAG = flagfile.read().strip()
with open('key', 'rb') as keyfile:
    KEY = keyfile.read()

def _compute_signature(msg):
    sig = hashlib.sha512(KEY + msg).hexdigest()
    return sig

def _split_users(auth_code):
    return auth_code.split(b':')

def _format_auth_code(auth_code):
    return binascii.b2a_hex(auth_code).decode()

def _read_auth_code(auth_code_str):
    return binascii.a2b_hex(auth_code_str)

def get_code():
    print('Enter usernames to authorize (hit ENTER when done)')
    names = []
    while True:
        new_name = input('Username: ')
        if 'admin' in new_name:
            print('This interface does not provide admin codes.')
            print()
            return
        elif new_name:
            names.append(new_name)
        else:
            break
    auth_code = bytes(':'.join(names), 'utf8')

    print('Auth code: {}'.format(_format_auth_code(auth_code)))
    print('Signature: {}'.format(_compute_signature(auth_code)))
    print()

def login():
    auth_code_str = input('Enter auth code: ')
    try:
        auth_code = _read_auth_code(auth_code_str)
    except binascii.Error:
        print('Invalid auth code')
        print()
        return

    sig = input('Enter signature: ')
    real_sig = _compute_signature(auth_code)
    if sig == real_sig:
        users = _split_users(auth_code)
        if b'admin' in users:
            print("Welcome to the system, administrator. Here's your flag: {}".format(FLAG))
        else:
            print("Welcome to the system. Unfortunately, only admins get flags.")
    else:
        print('Invalid signature')
    print()

while True:
    print('Menu:')
    print('1. Get authorization code')
    print('2. Login')
    print('3. Exit')
    cmd = input('Enter choice: ')
    if cmd == '1':
        get_code()
    elif cmd == '2':
        login()
    elif cmd == '3':
        break
    else:
        print('Unrecognized command')
