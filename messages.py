from __future__ import print_function, unicode_literals
from PyInquirer import prompt
import requests, secrets, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import crypto_backend




PASTEBIN = 'http://cs448lnx101.gcc.edu/posts/create'


def send_message(session_key, sender_private_key, recipient_public_key):
    # random nonce
    nonce = secrets.token_bytes(16)

    # get message (plaintext) from user
    message_prompt = [
        {
            'type': 'input',
            'name': 'message_text',
            'message': 'Enter Message Text',
        }
    ]
    message = prompt(message_prompt)

    # encrypt message with session key
    encrypted_message = crypto_backend.aes_encrypt(session_key, nonce, message)

    # rsa encrypt to get encrypted session key
    encrypted_session_key = crypto_backend.rsa_encrypt(session_key, recipient_public_key)

    # sign encrypted message with sender's private key
    signature = crypto_backend.sign_message(encrypted_message+nonce+encrypted_session_key, sender_private_key)

    # create json object with message info
    message_info = {
        'message': encrypted_message,
        'nonce': nonce,
        'encrypted_session_key': encrypted_session_key,
        'signature': signature
    }

    jsonified = json.JSONEncoder().encode(message_info)

    # post to pastebin with header that includes incrementing value to indicate order of
    # messages in the conversation
    requests.post(PASTEBIN, data={jsonified})

def receive_message(sender_public_key, signature, encrypted_message, encrypted_session_key, nonce, receiver_private_key):
    # verify message using RSA verify
    crypto_backend.verify_message(sender_public_key, signature, encrypted_message)
    
    # decrypt session key with RSA decrypt
    session_key = crypto_backend.rsa_decrypt(receiver_private_key, encrypted_session_key)

    # decrypt message with decrypted session key
    plaintext = crypto_backend.aes_decrypt(session_key, nonce, encrypted_message)

    print(plaintext)
