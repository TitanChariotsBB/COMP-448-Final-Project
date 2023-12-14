from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import secrets # Use this for generating random byte strings (keys, etc.)
from time import perf_counter
from inspect import cleandoc # Cleans up indenting in multi-line strings (""")

#
# Returns: An rsa.RSAPrivateKey object (which contains both the private key
#   and its corresponding public key; use .public_key() to obtain it).
#
RSA_KEY_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537
def rsa_gen_keypair():
    return rsa.generate_private_key(
            key_size = RSA_KEY_BITS,
            public_exponent = RSA_PUBLIC_EXPONENT
            )


#
# Argument: An rsa.RSAPrivateKey object
#
# Returns: An ASCII/UTF-8 string serialization of the private key using the
#   PKCS-8 format and PEM encoding. Does not encrypt the key for at-rest
#   storage.
#
def rsa_serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    return pem.decode('ASCII')

#
# Argument: A string containing an unencrypted RSA private key in PEM format.
#   Note that this also includes the matching public key (i.e., a PEM
#   "private key" serialization includes both halves of the keypair).
#
# Returns: An rsa.RSAPrivateKey object consisting of the deserialized key.
#
def rsa_deserialize_private_key(pem_privkey):
    private_key = serialization.load_pem_private_key(pem_privkey.encode('ASCII'))
    return private_key

#
# Argument: An rsa.RSAPublicKey object
#
# Returns: An ASCII/UTF-8 serialization of the public key using the
#   SubjectPublicKeyInfo format and PEM encoding.
#
def rsa_serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('ASCII')

#
# Argument: A string containing an RSA public key in PEM format.
#
# Returns: An rsa.RSAPublicKey object consisting of the deserialized key.
#
def rsa_deserialize_public_key(pem_pubkey):
    public_key = serialization.load_pem_public_key(pem_pubkey.encode('ASCII'))
    return public_key

#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
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

#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key of the
#       message recipient.
#   plaintext: The ciphertext message to be decrypted (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
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

#
# Encrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key. This should either be randomly
#       generated, or derived from a password using a secure key derivation
#       function.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode. It is imperative
#       that this be randomly generated, and NEVER reused after being used
#       once to encrypt a single message. (This is because each time you
#       encrypt a message with the same nonce in CTR mode, the counter starts
#       fresh from 0 again, meaning the initial blocks will have been XORed
#       with the same keystream as the previous message - allowing the key to
#       be trivially recovered by comparing the two.)
#           (N.B.: Even though we are using AES-256, i.e. a key size of 256
#           bits, the nonce is still 128 bits, because the block size of AES
#           is always 128 bits. A longer key just increases the number of
#           rounds performed.)
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: The encrypted message (ciphertext), as a raw byte string.
#
def aes_encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

#
# Decrypts a plaintext message using AES-256 in CTR (Counter) mode.
#
# Arguments:
#   key: A 256-bit (32-byte) secret key.
#   nonce: A 128-bit (16-byte) nonce to use with CTR mode.
#   ciphertext: The ciphertext message to be decrypted (as a raw byte string).
#
# No restrictions are placed on the values of key and nonce, but obviously,
# if they don't match the ones used to encrypt the message, the result will
# be gibberish.
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def aes_decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

#
# Encrypts a plaintext message using AES-256-CTR using a randomly generated
# session key and nonce.
#
# Argument: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   session_key: The randomly-generated 256-bit session key used to encrypt
#       the message (as a raw byte string).
#   nonce: The randomly-generated 128-bit nonce used in the encryption (as a
#       raw byte string).
#   ciphertext: The encrypted message (as a raw byte string).
#
def aes_encrypt_with_random_session_key(plaintext):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    ciphertext = aes_encrypt(key, nonce, plaintext)
    return key, nonce, ciphertext

#
# Encrypt a message using AES-256-CTR and a random session key, which in turn
# is encrypted with RSA so that it can be decrypted by the given public key.
#
# Arguments:
#   public_key: An rsa.RSAPublicKey object containing the public key of the
#       message recipient.
#   plaintext: The plaintext message to be encrypted (as a raw byte string).
#
# Returns: A tuple containing the following elements:
#   encrypted_session_key: The randomly-generated AES session key, encrypted
#       using RSA with the given public key (as a raw byte string).
#   nonce: The randomly-generated nonce used in the AES-CTR encrpytion (as a
#       raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
def encrypt_message_with_aes_and_rsa(public_key, plaintext):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    ciphertext = aes_encrypt(key,nonce,plaintext)

    encrypted_session_key = rsa_encrypt(public_key, key)
    return (encrypted_session_key, nonce, ciphertext)

#
# Decrypt a message that has been encrypted with AES-256-CTR, using an
# RSA-encrypted session key and an unencrypted nonce.
#
# Arguments:
#   private_key: An rsa.RSAPrivateKey object containing the private key that
#       will be used to decrypt the session key.
#   encrypted_session_key: The RSA-encrypted session key that will be used to
#       decrypt the actual message with AES-256-CTR (as a raw byte string).
#   nonce: The nonce that will be used to decrypt the message with
#       AES-256-CTR (as a raw byte string).
#   ciphertext: The AES-256-CTR-encrypted message (as a raw byte string).
#
# Returns: The decrypted message (plaintext), as a raw byte string.
#
def decrypt_message_with_aes_and_rsa(
        private_key, encrypted_session_key, nonce, ciphertext):
    decrypted_session_key = rsa_decrypt(private_key, encrypted_session_key)
    plaintext = aes_decrypt(decrypted_session_key,nonce,ciphertext)

    return plaintext