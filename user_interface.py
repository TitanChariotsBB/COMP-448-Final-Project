from __future__ import print_function, unicode_literals
from pyfiglet import Figlet
from PyInquirer import prompt
from pprint import pprint

import os
import requests

import crypto_backend
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# App actions
Q = 'Quit app'
A = 'Add contact'
P = 'Publish contact info'
D = 'Delete contact'
C = 'Start secure chat'
R = 'Reset all data'

# URLs
USER = 'user_info.jsonl'
CONTACTS = 'contacts.jsonl'
PASTEBIN = 'http://cs448lnx101.gcc.edu/posts/create'

#
# Prints a cool opening message
#
def opening_msg():
    f = Figlet(font = 'slant')
    print(f.renderText("Welcome to GCC SECA"))
    print("(Grove City College Secure Encrypted Chat App)\n")

#
# Returns: true if user has initialized info, false if not
#
def has_info() -> bool:
    try:
        return os.stat(USER).st_size > 0
    except:
        print("ERROR: cannot find `user_info.json`")
        return False

#
# Prompts the user for full name and verification code, 
# then generates an RSA keypair, then adds this information to user_info.json
# 
def initialize_user():
    # Creates new file or clears it if it exists
    open(USER, 'w+').close()

    print("To get started with this app, we need some information to create a keypair.")
    print("Answer the prompts below and hit enter to confirm.")
    questions = [
        {
            'type': 'input',
            'name': 'first_name',
            'message': 'First name:',
        },
        {
            'type': 'input',
            'name': 'last_name',
            'message': 'Last name:',
        },
        {
            'type': 'input',
            'name': 'ver_code',
            'message': 'Verification code:',
        }
    ]
    # JSON object of form {'first_name': 'Christian'}
    answers = prompt(questions)
    keypair = crypto_backend.rsa_gen_keypair()
    public_key_pem = crypto_backend.rsa_serialize_public_key(keypair.public_key())
    packaged_public_key = {
        'owner': answers['first_name'] + " " + answers['last_name'],
        'pubkey': public_key_pem
    }
    jsonified_public = json.JSONEncoder().encode(packaged_public_key)

    private_key_pem = crypto_backend.rsa_serialize_private_key(keypair)
    packaged_private_key = {
        'owner': answers['first_name'] + " " + answers['last_name'],
        'pubkey': private_key_pem
    }
    jsonified_private = json.JSONEncoder().encode(packaged_private_key)

    user_info_file = open(USER, "w")
    user_info_file.write(jsonified_public + "\n")
    user_info_file.write(jsonified_private + "\n")
    user_info_file.close()

#
# Publishes the user's contact info (name, public key) to the pastebin site
#
def publish_info(): 
    msg = "Begin GCC SECA msg. CODE: pub\n"
    # Get public key
    msg += open(USER).readline()
    postId = requests.post(PASTEBIN, data={'contents': msg})
    print(f"Post ID: {postId.json()['id']}")

#
# Adds a contact (name and public key) to the contacts.jsonl address book
#
# Argument: the name of the public key to search for. Ex: "Christian Abbott"
# 
def add_contact(name):
    # TODO
    print("TODO")

#
# Removes a contact from the address book
#
# Argument: the name of the contatct. Ex: "Christian Abbott"
#
def remove_contact(name):
    # TODO: test this
    contacts_file = open(CONTACTS, 'r')
    lines = contacts_file.readlines()
    new_lines: list[str]
    count = 0
    for line in lines:
        if "name" not in line:
            new_lines[count] = line
            count += 1
    contacts_file.close()
    contacts_file = open(CONTACTS, "w+")
    for line in new_lines:
        contacts_file.write(line + "\n")

#
# Returns: true if user has contacts, false if not
#
def has_contacts() -> bool:
    try:
        return os.stat(CONTACTS).st_size > 0
    except:
        print("ERROR: cannot find `contacts.jsonl`")
        return False
    
#
# Resets all user data by clearing user_info.jsonl and contacts.jsonl
#
def reset_data():
    open(USER, 'w').close()
    open(CONTACTS, 'w').close()
    print("All data reset!")

# Main method contains the main application loop
def main():
    has_quit = False

    opening_msg()

    if not has_info(): initialize_user()

    while not has_quit:
        if not has_contacts(): list_of_actions = [P, A, R, Q]
        else: list_of_actions = [C, P, A, D, R, Q]

        main_menu_options = [
            {
                'type': 'list', 
                'name': 'action', 
                'message': 'What would you like to do?',
                'choices': list_of_actions
            }
        ]

        action = prompt(main_menu_options)['action']
        if action == Q: 
            has_quit = True
        elif action == R: 
            reset_data()
            initialize_user()
        elif action == P:
            publish_info()
        else:
            print(f"You have chosen {action}")
    
        

main()