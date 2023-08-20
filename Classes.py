# Robert Gleason and Jacob Sprouse
# version 7

import socket
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class Socket(object):
    @staticmethod
    def server():
        host_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return host_server_socket

    @staticmethod
    def host():
        server_host = socket.gethostname()
        return server_host

    @staticmethod
    def port():
        server_port = 9998
        return server_port

    @staticmethod
    def listening(received_decrypt, c_socket, s_socket, address_port):
        if received_decrypt == 'Bye' or received_decrypt == 'bye':
            c_socket.close()
            print('Back to listening...')
            s_socket.listen()
            c_socket, address_port = s_socket.accept()


class Cipher(object):
    @staticmethod
    def cipher_key(key):
        keyval = int(key) // 8
        cipher_key = get_random_bytes(keyval)
        return cipher_key

    @staticmethod
    def encryption_ecb(cipher_key, message, user):
        try:
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("Server_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == 'server':
                rsa_key_data = RSA.import_key(open("Client_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Invalid User.")
        except ValueError as ve:
            print("Error:", ve)

        cipher_key = Signature.decrypt_rsa_with_private_key(rsa_key, cipher_key)
        message_bytes = message.encode()
        encryption_cipher = AES.new(cipher_key, AES.MODE_ECB)
        encrypt_ciphertext = encryption_cipher.encrypt(pad(message_bytes, AES.block_size))
        return encrypt_ciphertext

    @staticmethod
    def decryption_ecb(cipher_key, received_message):
        decryption = AES.new(cipher_key, AES.MODE_ECB)
        decrypt_ciphertext = unpad(decryption.decrypt(received_message), AES.block_size)
        received_message = bytes.decode(decrypt_ciphertext)
        return received_message

    @staticmethod
    def encryption_cbc(cipher_key, message, iv, user):
        try:
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("Server_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == 'server':
                rsa_key_data = RSA.import_key(open("Client_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Invalid User.")
        except ValueError as ve:
            print("Error:", ve)

        cipher_key = Signature.decrypt_rsa_with_private_key(rsa_key, cipher_key)
        message_bytes = message.encode()
        encryption_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
        encrypt_ciphertext = encryption_cipher.encrypt(pad(message_bytes, AES.block_size))
        return encrypt_ciphertext

    @staticmethod
    def decryption_cbc(cipher_key, received_message, iv):
        decrypt_cipher_bytes = AES.new(cipher_key, AES.MODE_CBC, iv)
        decrypt_ciphertext = unpad(decrypt_cipher_bytes.decrypt(received_message), AES.block_size)
        received_message = bytes.decode(decrypt_ciphertext)
        return received_message

    @staticmethod
    def encryption_ofb(cipher_key, message, iv, user):
        try:
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("Server_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == 'server':
                rsa_key_data = RSA.import_key(open("Client_private_key.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Kill Yourself.")
        except ValueError as ve:
            print("Error:", ve)

        cipher_key = Signature.decrypt_rsa_with_private_key(rsa_key, cipher_key)
        message_bytes = message.encode()
        encrypt_message = AES.new(cipher_key, AES.MODE_OFB, iv)
        encrypted_cipher_text = encrypt_message.encrypt(message_bytes)
        return encrypted_cipher_text

    @staticmethod
    def decryption_ofb(cipher_key, received_message, iv):
        decrypt_cipher_bytes = AES.new(cipher_key, AES.MODE_OFB, iv)
        decrypt_ciphertext = decrypt_cipher_bytes.decrypt(received_message)
        received_message = bytes.decode(decrypt_ciphertext)
        return received_message


class Signature(object):
    @staticmethod
    def generate_rsa_key():
        """ Generate RSA key """
        key = RSA.generate(2048)
        return key

    @staticmethod
    def generate_private_key(key, file_name):
        """ Generate Private key """
        private_key = key.export_key()
        file_out = open(file_name, 'wb')
        file_out.write(private_key)
        file_out.close()
        return private_key

    @staticmethod
    def generate_public_key(key, file_name):
        public_key = key.publickey().export_key()
        file_out = open(file_name, 'wb')
        file_out.write(public_key)
        file_out.close()
        return public_key

    @staticmethod
    def encrypt_rsa(public_key, aes_key):
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypt_rsa_key = rsa_cipher.encrypt(aes_key)
        return encrypt_rsa_key

    @staticmethod
    def decrypt_rsa_with_private_key(private_key, encrypt_rsa_key):
        rsa_cipher = PKCS1_OAEP.new(private_key)
        decrypt_aes_key = rsa_cipher.decrypt(encrypt_rsa_key)
        return decrypt_aes_key
