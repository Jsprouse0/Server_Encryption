# Robert Gleason and Jacob Sprouse
# version 5

import socket
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES


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
    def encryption_ecb(cipher_key, message):
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
    def encryption_cbc(cipher_key, message, iv):
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
    def encryption_ofb(cipher_key, message, iv):
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
