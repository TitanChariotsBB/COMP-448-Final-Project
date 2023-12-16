from __future__ import print_function, unicode_literals
from PyInquirer import prompt
import requests, secrets, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import crypto_backend
from base64 import b64encode, b64decode




PASTEBIN = 'http://cs448lnx101.gcc.edu/posts/create'


def encrypt_message(sender_private_key_pem, recipient_public_key_pem, message):
    # random session key
    session_key = secrets.token_bytes(32)

    # random nonce
    nonce = secrets.token_bytes(16)

    # format message in UTF-8
    message = message.encode('utf-8')

    # encrypt message with session key
    encrypted_message = crypto_backend.aes_encrypt(session_key, nonce, message)

    # deserialize keys
    sender_private_key = crypto_backend.rsa_deserialize_private_key(sender_private_key_pem)
    recipient_public_key = crypto_backend.rsa_deserialize_public_key(recipient_public_key_pem)

    # rsa encrypt to get encrypted session key
    encrypted_session_key = crypto_backend.rsa_encrypt(recipient_public_key, session_key)

    # concatenate encrypted_message, nonce, and encrypted session key
    to_sign: bytes = encrypted_message + nonce + encrypted_session_key

    # sign encrypted message with sender's private key
    signature = sign_message(to_sign, sender_private_key)

    # create json object with message info
    packaged_message = {
        'sessionkey': b64encode(encrypted_session_key).decode('ascii'),
        'nonce': b64encode(nonce).decode('ascii'),
        'ciphertext': b64encode(encrypted_message).decode('ascii'),
        'signature': b64encode(signature).decode('ascii')
    }

    jsonified = json.JSONEncoder().encode(packaged_message)

    return jsonified

def decrypt_message(sender_public_key_pem, signature, encrypted_message, 
                    encrypted_session_key, nonce, receiver_private_key_pem):
    # deserialize keys
    receiver_private_key = crypto_backend.rsa_deserialize_private_key(receiver_private_key_pem)
    sender_public_key = crypto_backend.rsa_deserialize_public_key(sender_public_key_pem)

    # decode other pieces
    encrypted_session_key = b64decode(encrypted_session_key, validate = True)
    nonce = b64decode(nonce, validate = True)
    encrypted_message = b64decode(encrypted_message, validate = True)
    signature = b64decode(signature, validate = True)

    # concatenate encrypted_message, nonce, and encrypted session key
    to_verify: bytes = encrypted_message + nonce + encrypted_session_key

    try:
        # verify message using RSA verify
        verify_message(sender_public_key, signature, to_verify)
    except:
        print("This message is not verified as from the expected sender")
        return ""
    else:
        # decrypt session key with RSA decrypt
        session_key = crypto_backend.rsa_decrypt(receiver_private_key, encrypted_session_key)

        # decrypt message with decrypted session key
        plaintext = crypto_backend.aes_decrypt(session_key, nonce, encrypted_message)

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