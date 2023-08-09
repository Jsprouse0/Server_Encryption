# Robert Gleason and Jacob Sprouse
# Version 5
from Classes import Socket, Cipher


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

        # match cases for multiple AES modes
        match received_cipher_mode.decode():
            case 'ECB':
                decrypt_cipher = Cipher.decryption_ecb(received_key, received_bytes)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_cipher}")

                message_input = input("Input a message: \n")
                encrypt_text = Cipher.encryption_ecb(received_key, message_input)
                client_socket.send(encrypt_text)

                if decrypt_cipher == 'Bye' or decrypt_cipher == 'bye':
                    client_socket.close()
                    print('Back to listening...')
                    server_socket.listen()
                    client_socket, addr_port = server_socket.accept()

            case 'CBC':
                received_iv = client_socket.recv(1024)
                print(received_iv)

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

            case 'OFB':
                received_iv = client_socket.recv(1024)
                print(received_iv)

                decrypt_cipher = Cipher.decryption_ofb(received_key, received_bytes, received_iv)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_cipher}")

                message_input = input("Input a message my Boi: \n")
                encrypt_text = Cipher.encryption_ofb(received_key, message_input, received_iv)
                client_socket.send(encrypt_text)

                if decrypt_cipher == 'Bye' or decrypt_cipher == 'bye':
                    client_socket.close()
                    print('Back to listening...')
                    server_socket.listen()
                    client_socket, addr_port = server_socket.accept()
