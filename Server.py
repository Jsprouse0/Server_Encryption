import socket                                                                   # Robert Gleason and Jacob Sprouse
import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

# excess receiving overloads the server, try and fix


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
        if decrypt_cipher == 'Bye' or decrypt_cipher == 'bye':
            client_socket.close()
            print('Back to listening...')
            server_socket.listen()
            c_socket, address_port = server_socket.accept()


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


if __name__ == '__main__':
    # Creates a socket object that listens
    server_socket = Socket.server()

    # get host name
    host = Socket.host()

    # the socket listens at port 7777 that doesn't interfere with other processes
    port = Socket.port()

    # bind the socket to the port, bridge between host && port
    server_socket.bind((host, port))

    # start listening
    server_socket.listen()
    print("Waiting for connection.....")

    # addr_port is a tuple that contains both the address and the port number
    # clientSocket is the communication variable between host and port
    client_socket, addr_port = server_socket.accept()

    print("\nGot a connection from " + str(addr_port))

    while True:
        # Client response, Cipher mode, the key, and message
        received_cipher_mode = client_socket.recv(1024)
        received_key = client_socket.recv(1024)
        received_bytes = client_socket.recv(1024)

        # sleep so the sockets are not flooded
        time.sleep(2.3)

        # match cases for multiple AES modes
        match received_cipher_mode.decode():
            case 'ECB':
                decrypt_cipher = Cipher.decryption_ecb(received_key, received_bytes)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_cipher}")

                message_input = input("Input a message: \n")
                encrypt_text = Cipher.encryption_ecb(received_key, message_input)

            case 'CBC':
                received_iv = client_socket.recv(1024)

                decrypt_cipher = Cipher.decryption_cbc(received_key, received_bytes, received_iv)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_cipher}")

                message_input = input("Input a message my Boi: \n")
                encrypt_text = Cipher.encryption_cbc(received_key, message_input, received_iv)

        client_socket.send(encrypt_text)

        if decrypt_cipher == 'Bye' or decrypt_cipher == 'bye':
            client_socket.close()
            print('Back to listening...')
            server_socket.listen()
            client_socket, addr_port = server_socket.accept()
