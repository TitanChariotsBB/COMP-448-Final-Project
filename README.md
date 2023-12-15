# GCC SECA

Grove City College Secure Encrypted Chat App

## How to install

To install, clone the git repo in a directory of your choice. Next, use pip to install the required libraries: `pip install -r requirements.txt`.

## How to run

To run, type: `python user_interface.py`. Upon initial installation, the program will ask for a name. After this is provided, it will generate an RSA keypair. To exchange messages using the app, you will need to add contacts, and be added as a contact by others. To publish your contact info to the network, select "Publish contact info." At this point, your friends can add you as a contact by searching for your name. Assuming your friends have also published their info, you can add them as contacts through selecting "Add contact" then searching for your friends by name. To send a message, select "Send message." To fetch the most recent message sent to you, select "Fetch latest message."
