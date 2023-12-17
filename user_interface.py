from __future__ import print_function, unicode_literals
from pyfiglet import Figlet
from PyInquirer import prompt
from pprint import pprint

import os
import requests

import crypto_backend
import messages
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# App actions
Q = 'Quit app'
A = 'Add contact'
P = 'Publish contact info'
L = 'List contacts'
D = 'Delete contact'
S = 'Send message'
F = 'Fetch latest message'
R = 'Reset all data'

PUBLISH_FLAG = 'Begin GCC SECA msg. CODE: pub\n'
MESSAGE_FLAG = 'Begin GCC SECA msg. CODE: msg\n'

# URLs
USER = 'user_info.jsonl'
CONTACTS = 'contacts.jsonl'
PASTEBIN = 'http://cs448lnx101.gcc.edu'

user_info = []
contacts = []

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
        print("Creating new `user_info.json`")
        print()
        return False

#
# Prompts the user for full name and verification code, 
# then generates an RSA keypair, then adds this information to user_info.json
# 
def initialize_user():
    # Creates new file or clears it if it exists
    open(USER, 'w+').close()

    print("To get started with this app, we need some information to create a keypair.")
    print("Answer the prompt below and hit enter to confirm.")
    question = [
        {
            'type': 'input',
            'name': 'user_name',
            'message': 'Your name (will be displayed publicly): ',
        }
    ]
    # JSON object of form {'first_name': 'Christian'}
    answers = prompt(question)
    keypair = crypto_backend.rsa_gen_keypair()
    public_key_pem = crypto_backend.rsa_serialize_public_key(keypair.public_key())
    packaged_public_key = {
        'owner': answers['user_name'],
        'pubkey': public_key_pem
    }
    jsonified_public = json.JSONEncoder().encode(packaged_public_key)

    private_key_pem = crypto_backend.rsa_serialize_private_key(keypair)
    packaged_private_key = {
        'owner': answers['user_name'],
        'privkey': private_key_pem
    }
    jsonified_private = json.JSONEncoder().encode(packaged_private_key)
    user_info_file = open(USER, "w")
    user_info_file.write(jsonified_public + "\n")
    user_info_file.write(jsonified_private + "\n")
    user_info_file.close()
    print()

#
# Loads user info (from user_info.jsonl) into a list of json objects
#
def load_user_info():
    f = open(USER, 'r')
    lines = f.readlines()
    for line in lines:
        user_info.append(json.loads(line))

#
# Returns user's name
#
def get_user_name():
    return user_info[0]["owner"]

#
# Publishes the user's contact info (name, public key) to the pastebin site
#
def publish_info(): 
    msg = PUBLISH_FLAG
    # Get public key
    msg = PUBLISH_FLAG + json.JSONEncoder().encode(user_info[0])
    postId = requests.post(PASTEBIN + '/posts/create', data={'contents': msg})
    print(f"Post ID: {postId.json()['id']}")
    print()

def load_contacts():
    if (os.stat(CONTACTS).st_size > 0):
        f = open(CONTACTS, 'r')
        lines = f.readlines()
        for line in lines:
            contacts.append(json.loads(line))
    else:
        contacts = []

def write_contacts():
    f = open(CONTACTS, 'w')
    for contact in contacts:
        f.write(json.JSONEncoder().encode(contact) + "\n")

#
# Adds a contact (name and public key) to the contacts.jsonl address book
# 
def add_contact():
    contact_found = False
    name_prompt = [{'type': 'input', 'name': 'name', 'message': 'Name to search for: '}]
    name = prompt(name_prompt)['name']
    response = json.loads(requests.get(PASTEBIN + '/posts/get/latest').content)
    id = int(response['posts'][0]['id'])
    content = response['posts'][0]['contents']
    while not contact_found:
        if PUBLISH_FLAG in content: 
            if name in content:
                contact_found = True
                contacts.append(json.loads(content.replace(PUBLISH_FLAG, "")))
                print(f"Added contact: {name}")
                break
        id -= 1
        response = json.loads(requests.get(PASTEBIN + f'/posts/view/{id}').content)
        if not response['error']: 
            content = response['contents']
        if id == 0:
            print(f"Could not find {name}")
    print()

#
# Returns a list of all contact names in the contacts array
#
def list_of_contact_names() -> "list[str]":
    contact_names = []
    for contact in contacts:
        contact_names.append(contact["owner"])
    return contact_names

#
# Lists all contacts in contacts.jsonl
#
def list_contacts():
    for contact in list_of_contact_names():
        print(contact)
    print()

#
# Returns the serialized public key of the given contact
#
def get_contact_public_key(contact_name):
    for contact in contacts:
        if contact["owner"] == contact_name:
            return contact["pubkey"]
    # This should probably throw an exception
    return None

#
# Returns the user's public key
#
def get_public_key():
    return user_info[0]["pubkey"]

#
# Returns the user's private key
#
def get_private_key():
    return user_info[1]["privkey"]

#
# Removes a contact from the address book
#
def remove_contact():
    name_prompt = [
        {
            'type': 'list', 
            'name': 'name', 
            'message': 'Contact to delete: ',
            'choices': list_of_contact_names()
        }
    ]
    name = prompt(name_prompt)['name']
    for contact in contacts:
        if contact["owner"] == name: contacts.remove(contact)
    print(f"Removed contact: {name}\n\n")
    print()

#
# Returns: true if user has contacts, false if not
#
def has_contacts() -> bool:
    return len(contacts) > 0
    
#
# Gets user input and calls messages' send_message function 
#   with the necessary keys
#
def send_message():
    message_prompt = [
        {
            'type': 'list',
            'name': 'recipient',
            'message': 'Recipient:',
            'choices': list_of_contact_names()
        },
        {
            'type': 'input',
            'name': 'text',
            'message': 'Message:',
        }
    ]
    message_data = prompt(message_prompt)
    recipient = message_data['recipient']
    message = str(message_data['text'])

    recipient_public_key = get_contact_public_key(recipient) # for encryption
    sender_private_key = get_private_key() # for signing

    message_data = messages.encrypt_message(
        sender_private_key_pem = sender_private_key, 
        recipient_public_key_pem = recipient_public_key, 
        message = message
    )

    msg = MESSAGE_FLAG + f"RECIPIENT: {recipient}\n" + \
          f"SENDER: {get_user_name()}\n" + message_data

    postId = requests.post(PASTEBIN + '/posts/create', data={'contents': msg})
    print("Message sent successfully!")
    # print(f"Post ID: {postId.json()['id']}")
    print()

#
# Scans the pastebin for the latest message addressed to the user, 
#   then decrypts and displays it
#
def fetch_message():
    message_found = False;
    sender = ""
    response = requests.get(PASTEBIN + '/posts/get/latest')
    id = int(json.loads(response.content)['posts'][0]['id'])
    content = json.loads(response.content)['posts'][0]['contents']
    while not message_found:
        if MESSAGE_FLAG in content: 
            if f"RECIPIENT: {get_user_name()}" in content:
                message_found = True
                message = content
                lines = message.split("\n")
                try:
                    sender = lines[2].replace("SENDER: ", "").strip().replace("\n", "")
                except:
                    break
                json_bundle = json.loads(lines[3])
                break
        id -= 1
        response = requests.get(PASTEBIN + f'/posts/view/{id}')
        if not json.loads(response.content)['error']:
            content = json.loads(response.content)['contents']
        if id == 0:
            print(f"Could not find any messages")
            return
    # print("Sender: " + sender)
    # print("JSON bundle: " + str(json_bundle))

    sender_public_key = get_contact_public_key(sender) # for verification
    recipient_private_key = get_private_key() # for decryption

    plain_text = (messages.decrypt_message(
        sender_public_key_pem = sender_public_key,
        signature = json_bundle["signature"],
        encrypted_message = json_bundle["ciphertext"],
        encrypted_session_key = json_bundle["sessionkey"],
        nonce = json_bundle["nonce"],
        receiver_private_key_pem = recipient_private_key
    )).decode("utf-8")

    print(f"---\nMessage from {sender}: {plain_text}\n---")
    print()



#
# Resets all user data by clearing user_info.jsonl and contacts.jsonl
#
def reset_data():
    open(USER, 'w').close()
    open(CONTACTS, 'w').close()
    print("All data reset!")
    print()

# Main method contains the main application loop
def main():
    has_quit = False

    opening_msg()

    if not has_info(): initialize_user()
    load_user_info()
    load_contacts()

    while not has_quit:
        if not has_contacts(): list_of_actions = [P, A, R, Q]
        else: list_of_actions = [S, F, P, A, L, D, R, Q]

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
            write_contacts()
        elif action == R: 
            reset_data()
            initialize_user()
            load_user_info()
            load_contacts()
        elif action == P:
            publish_info()
        elif action == A:
            add_contact()
        elif action == L:
            list_contacts()
        elif action == D:
            remove_contact()
        elif action == S:
            send_message()
        elif action == F:
            fetch_message()
        else:
            print(f"You have chosen {action}")
    
        

main()
