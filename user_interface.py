from __future__ import print_function, unicode_literals
from pyfiglet import Figlet
from PyInquirer import prompt
from pprint import pprint

import os

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
        return os.stat("user_info.json").st_size > 0
    except:
        print("ERROR: cannot find `user_info.json`")
        return False

#
# Prompts the user for full name and verification code, 
# then generates an RSA keypair, then adds this information to user_info.json
# 
def initialize_user():
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
    pprint(answers)
    # TODO: Generate keypair and add to user_info.json

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
    # TODO
    print("TODO")

#
# Returns: true if user has contacts, false if not
#
def has_contacts() -> bool:
    try:
        return os.stat("contacts.jsonl").st_size > 0
    except:
        print("ERROR: cannot find `contacts.jsonl`")
        return False

def main():
    has_quit = False

    opening_msg()

    if not has_info(): initialize_user()

    while (not has_quit):
        if not has_contacts(): list_of_actions = ['Add contact', 'Reset all data', 'Quit app']
        else: list_of_actions = ['Add contact', 'Delete contact', 'Start secure chat', 'Reset all data', 'Quit app']

        main_menu_options = [
            {
                'type': 'list', 
                'name': 'action', 
                'message': 'What would you like to do?',
                'choices': list_of_actions
            }
        ]

        chosen_action = prompt(main_menu_options)['action']
        if (chosen_action == "Quit app"): has_quit = True

        print(f"You have chosen {chosen_action}")
    
        

main()