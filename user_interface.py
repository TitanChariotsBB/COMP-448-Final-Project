from __future__ import print_function, unicode_literals
from pyfiglet import Figlet
from PyInquirer import prompt
from pprint import pprint

#
# Prints a cool opening message
#
def opening_msg():
    f = Figlet(font = 'slant')
    print(f.renderText("Welcome to GCC SECA"))
    print("(Grove City College Secure Encrypted Chat App)\n")

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

#
# Adds a contact (name and public key) to the contacts.jsonl address book
#
# Argument: the name of the public key to search for. Ex: "Christian Abbott"
# 
def add_contact(name):
    # TODO
    print("TODO")


def main():
    opening_msg()

    # TODO: Check if user has uninitialized user info
    init_state = False

    if init_state: initialize_user()



main()

initialize_user()