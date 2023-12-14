from __future__ import print_function, unicode_literals
from PyInquirer import prompt
import requests, secrets, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding




PASTEBIN = 'http://cs448lnx101.gcc.edu/posts/create'


def send_message(session_key, sender_private_key, recipient_public_key):
    # random nonce
    nonce = secrets.token_bytes(16)

    # get message (plaintext) from user
    questions = [
        {
            'type': 'input',
            'name': 'message_text',
            'message': 'Enter Message Text',
        }
    ]
    answers = prompt(questions)

    # encrypt message with session key
    encrypted_message = aes_encrypt(session_key, nonce, answers)

    # rsa encrypt to get encrypted session key
    encrypted_session_key = rsa_encrypt(session_key, recipient_public_key)

    # sign encrypted message with sender's private key
    signature = sign_message(encrypted_message+nonce+encrypted_session_key, sender_private_key)

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
    verify_message(sender_public_key, signature, encrypted_message)
    
    # decrypt session key with RSA decrypt
    session_key = rsa_decrypt(receiver_private_key, encrypted_session_key)

    # decrypt message with decrypted session key
    plaintext = aes_decrypt(session_key, nonce, encrypted_message)

    print(plaintext)




def aes_encrypt(session_key, nonce, plaintext):
    cipher = Cipher(algorithms.AES256(session_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_message(public_key, signature, message):
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return plaintext