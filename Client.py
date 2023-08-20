# Robert Gleason and Jacob Sprouse
# Version 7

import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Classes import Socket, Cipher, Signature
from Crypto.PublicKey import RSA

# create socket object
connectionSocket = Socket.server()
host = Socket.host()
port = Socket.port()
connectionSocket.connect((host, port))
connection = True

cipher_mode = input('Input a mode my boi: \n')

key_type = int(input('Input an AES key: \n'))
aes_key = Cipher.cipher_key(key_type)

name = input('Input the User: \n')

""" Create the RSA private/public key for client """
rsa_key = Signature.generate_rsa_key()
rsa_private_key_generate = Signature.generate_private_key(rsa_key, "Client_private_key.pem")
rsa_public_key_generate = Signature.generate_public_key(rsa_key, "Client_public_key.pem")

""" Read the public key and private into data """
rsa_client_private_key_data = RSA.import_key(open("Client_private_key.pem").read()).export_key()
rsa_client_public_key_data = RSA.import_key(open("Client_public_key.pem").read()).export_key()

""" Read the private key into a variable"""
rsa_client_private_key = RSA.import_key(rsa_client_private_key_data)

while connection:
    """ send the client public key for server encryption """
    connectionSocket.send(rsa_client_public_key_data)
    connectionSocket.send(cipher_mode.encode())     # The mode selected for encryption
    message = input('Input a message my boi: \n')   # input a message to be sent over
    print(message)

    """ create an IV for every connection session (CBC or OFB) """
    iv = get_random_bytes(AES.block_size)

    """ receive the servers public key for client encryption """
    rsa_server_public_key_data = connectionSocket.recv(2048)    # receive the servers public key for encryption
    rsa_server_public_key = RSA.import_key(rsa_server_public_key_data)  # import the key from the data
    print(f'Server {rsa_server_public_key}')

    # Cipher mode check
    match cipher_mode:
        case 'ECB':
            encrypted_aes_key = Signature.encrypt_rsa(rsa_server_public_key, aes_key)
            encrypt_text = Cipher.encryption_ecb(encrypted_aes_key, message, name)

            # sends message_input and aes_encrypted key across socket to server for more secure transport
            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(encrypt_text)

            """ Server message and encrypted key"""
            received_server_message = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)

            """ decrypt the rsa key and then the message"""
            decrypt_rsa_key = Signature.decrypt_rsa_with_private_key(rsa_client_private_key, received_server_key)
            decrypt_message = Cipher.decryption_ecb(decrypt_rsa_key, received_server_message)

        case 'CBC':
            encrypted_aes_key = Signature.encrypt_rsa(rsa_server_public_key, aes_key)
            encrypt_text = Cipher.encryption_cbc(encrypted_aes_key, message, iv, name)

            # sends message_input across socket to server
            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(encrypt_text)
            time.sleep(0.2)
            connectionSocket.send(iv)

            """ Server message and encrypted key"""
            received_server_message = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)

            """ decrypt the rsa key and then the message"""
            decrypt_rsa_key = Signature.decrypt_rsa_with_private_key(rsa_client_private_key, received_server_key)
            decrypt_message = Cipher.decryption_cbc(decrypt_rsa_key, received_server_message, iv)

        case 'OFB':
            encrypted_aes_key = Signature.encrypt_rsa(rsa_server_public_key, aes_key)
            encrypt_text = Cipher.encryption_ofb(encrypted_aes_key, message, iv, name)

            # sends message_input across socket to server
            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(encrypt_text)
            time.sleep(0.2)
            connectionSocket.send(iv)

            """ Server message and encrypted key"""
            received_server_message = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)

            """ decrypt the rsa key and then the message"""
            decrypt_rsa_key = Signature.decrypt_rsa_with_private_key(rsa_client_private_key, received_server_key)
            decrypt_message = Cipher.decryption_ofb(decrypt_rsa_key, received_server_message, iv)

    print(encrypt_text)

    print(f"The cipher text is: {received_server_message}\nAnd the message is: {decrypt_message}")

    if decrypt_message.lower() == 'bye':
        connectionSocket.close()
        connection = False
