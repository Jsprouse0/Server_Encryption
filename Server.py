import socket                                                                   # Robert Gleason and Jacob Sprouse
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
        server_port = 7777
        return server_port


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
        # Client response
        received_bytes = client_socket.recv(1024)

        # decryption key
        received_key = client_socket.recv(1024)
        decrypt_cipher = AES.new(received_key, AES.MODE_ECB)
        ciphertext = unpad(decrypt_cipher.decrypt(received_bytes), AES.block_size)

        received_message = bytes.decode(ciphertext)
        print(f"The cipher text is {received_message}")

        # Server message
        message = input()
        message_encode = message.encode()

        # encryption
        encrypt_cipher = AES.new(received_key, AES.MODE_ECB)
        server_cipher_text = encrypt_cipher.encrypt(pad(message_encode, AES.block_size))

        client_socket.send(server_cipher_text)

        if received_message == 'Bye' or received_message == 'bye':
            client_socket.close()
            print('Back to listening...')
            server_socket.listen()
            client_socket, addr_port = server_socket.accept()

