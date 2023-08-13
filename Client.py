# Robert Gleason and Jacob Sprouse
# Version 5

import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Classes import Socket, Cipher, Signature

# create socket object
connectionSocket = Socket.server()
host = Socket.host()
port = Socket.port()
connectionSocket.connect((host, port))
connection = True
cipher_mode = input('Input a mode my boi: \n')

key_type = int(input('Input an AES key: \n'))
aes_key = Cipher.cipher_key(key_type)

rsa_key = Signature.generate_rsa_key()
rsa_client_private_key = Signature.generate_private_key(rsa_key, "Client_private_key.pem")
rsa_client_public_key = Signature.generate_public_key(rsa_key, "Client_public_key.pem")

while connection:
    # Client message_input
    connectionSocket.send(cipher_mode.encode())
    message = input('Input a message my boi: \n')
    print(message)

    iv = get_random_bytes(AES.block_size)

    # Cipher mode check
    match cipher_mode:
        case 'ECB':
            encrypt_text = Cipher.encryption_ecb(aes_key, message)

            # sends message_input across socket to server
            connectionSocket.send(aes_key)
            connectionSocket.send(encrypt_text)

            # Server Response
            received_server_message = connectionSocket.recv(1024)
            received_message = Cipher.decryption_ecb(aes_key, received_server_message)

        case 'CBC':
            encrypt_text = Cipher.encryption_cbc(aes_key, message, iv)

            # sends message_input across socket to server
            connectionSocket.send(aes_key)
            connectionSocket.send(encrypt_text)
            time.sleep(0.2)
            connectionSocket.send(iv)

            # Server Response
            received_server_message = connectionSocket.recv(1024)
            decrypt_response = Cipher.decryption_cbc(aes_key, received_server_message, iv)
        case 'OFB':
            encrypt_text = Cipher.encryption_ofb(aes_key, message, iv)

            # sends message_input across socket to server
            connectionSocket.send(aes_key)
            connectionSocket.send(encrypt_text)
            time.sleep(0.2)
            connectionSocket.send(iv)

            # Server Response
            received_server_message = connectionSocket.recv(1024)
            decrypt_response = Cipher.decryption_ofb(aes_key, received_server_message, iv)

    print(encrypt_text)

    print(f"The cipher text is: {received_server_message}\nAnd the message is: {decrypt_response}")

    if decrypt_response == 'Bye' or decrypt_response == 'bye':
        connectionSocket.close()
        connection = False
