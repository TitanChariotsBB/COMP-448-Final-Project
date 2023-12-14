from __future__ import print_function, unicode_literals
from pyfiglet import Figlet
from PyInquirer import prompt
from pprint import pprint

def opening_msg():
    f = Figlet(font = 'slant')
    print(f.renderText("Welcome to GCC SECA"))
    print("(Grove City College Secure Encrypted Chat App)\n")

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



def main():
    opening_msg()

    # TODO: Check if user has uninitialized user info
    init_state = False

    if init_state: initialize_user()



main()

initialize_user()