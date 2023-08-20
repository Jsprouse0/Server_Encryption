# Robert Gleason and Jacob Sprouse
# Version 9
from Classes import Socket, Cipher, Signature
from Crypto.PublicKey import RSA


if __name__ == '__main__':
    # Creates a socket object that listens
    server_socket = Socket.server()

    # get host name
    host = Socket.host()
    name = 'Server'     # the server name to be sent back to client
    # the socket listens at port 9998 that doesn't interfere with other processes
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

    """ Creates RSA key for server"""
    rsa_key = Signature.generate_rsa_key()
    rsa_server_private_key_generate = Signature.generate_private_key(rsa_key, "Server_private_key.pem")
    rsa_server_public_key_generate = Signature.generate_public_key(rsa_key, "Server_public_key.pem")

    """ Reads the keys from the generated files and exports the key """
    rsa_server_public_key_data = RSA.import_key(open("Server_public_key.pem").read()).export_key()
    rsa_server_private_key_data = RSA.import_key(open("Server_private_key.pem").read()).export_key()

    """ imports the data of the server's private key and from exported data"""
    rsa_server_private_key = RSA.import_key(rsa_server_private_key_data)

    """ send the RSA server public key for client encryption"""
    client_socket.send(rsa_server_public_key_data)

    while True:
        # Client response, Cipher mode, the key, and message
        received_rsa_client_public_key = client_socket.recv(2048)
        rsa_client_public_key = RSA.import_key(received_rsa_client_public_key)
        print(f'Client {rsa_client_public_key}')

        received_cipher_mode = client_socket.recv(1024)
        received_aes_key = client_socket.recv(1024)
        received_bytes = client_socket.recv(1024)

        """ decrypts the rsa encrypted key with the servers private key """
        decrypted_aes_key = Signature.decrypt_rsa_with_private_key(rsa_server_private_key, received_aes_key)

        # match cases for multiple AES modes
        match received_cipher_mode.decode():
            case 'ECB':
                decrypt_message = Cipher.decryption_ecb(decrypted_aes_key, received_bytes)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_message}\n\n")

                message_input = input("Input a message: \n")

                """ encrypts the key again to be sent back to client """
                encrypted_aes_key = Signature.encrypt_rsa(rsa_client_public_key, decrypted_aes_key)
                encrypt_text = Cipher.encryption_ecb(encrypted_aes_key, message_input, name)
                client_socket.send(encrypt_text)

                """ ends the connection with the client and listens for new connection """
                if decrypt_message.lower() == 'bye':
                    client_socket.close()
                    print('Back to listening...')
                    server_socket.listen()
                    client_socket, addr_port = server_socket.accept()

            case 'CBC':
                received_iv = client_socket.recv(1024)

                decrypt_message = Cipher.decryption_cbc(decrypted_aes_key, received_bytes, received_iv)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_message}")

                message_input = input("Input a message my Boi: \n")
                print(message_input)

                """encrypts the aes key again and then the text to be sent to client """
                encrypted_aes_key = Signature.encrypt_rsa(rsa_client_public_key, decrypted_aes_key)
                encrypt_text = Cipher.encryption_cbc(encrypted_aes_key, message_input, received_iv, name)

                client_socket.send(encrypt_text)
                client_socket.send(encrypted_aes_key)

                if decrypt_message.lower() == 'bye':
                    client_socket.close()
                    print('Back to listening...')
                    server_socket.listen()
                    client_socket, addr_port = server_socket.accept()

            case 'OFB':
                received_iv = client_socket.recv(1024)

                """ decrypt the OFB encrypted message to the server """
                decrypt_message = Cipher.decryption_ofb(decrypted_aes_key, received_bytes, received_iv)

                print(f"The cipher text is: {received_bytes}\nAnd the message is: {decrypt_message}")

                message_input = input("Input a message my Boi: \n")
                encrypted_aes_key = Signature.encrypt_rsa(rsa_client_public_key, decrypted_aes_key)
                encrypt_text = Cipher.encryption_ofb(encrypted_aes_key, message_input, received_iv, name)
                client_socket.send(encrypt_text)

                if decrypt_message.lower() == 'bye':
                    client_socket.close()
                    print('Back to listening...')
                    server_socket.listen()
                    client_socket, addr_port = server_socket.accept()
