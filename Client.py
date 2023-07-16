# Robert Gleason and Jacob Sprouse
import socket
from Server import Socket, Cipher
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

# create socket object
connectionSocket = Socket.server()
host = Socket.host()
port = Socket.port()
connectionSocket.connect((host, port))
connection = True
cipher_mode = input('Input a mode my boi: \n')

key_type = int(input('Input a key: \n'))
key = Cipher.cipher_key(key_type)


while connection:
    # Client message_input
    connectionSocket.send(cipher_mode.encode())
    message = input('Input a message my boi: \n')

    iv = get_random_bytes(AES.block_size)

    # Cipher mode check
    match cipher_mode:
        case 'ECB':
            encrypt_text = Cipher.encryption_ecb(key, message)

            # sends message_input across socket to server
            connectionSocket.send(key)
            connectionSocket.send(encrypt_text)

            # Server Response
            received_server_message = connectionSocket.recv(1024)
            received_message = Cipher.decryption_ecb(key, received_server_message)

        case 'CBC':
            encrypt_text = Cipher.encryption_cbc(key, message, iv)

            # sends message_input across socket to server
            connectionSocket.send(key)
            connectionSocket.send(encrypt_text)
            connectionSocket.send(iv)

            # Server Response
            received_server_message = connectionSocket.recv(1024)
            decrypt_response = Cipher.decryption_cbc(key, received_server_message, iv)

    print(encrypt_text)

    print(f"The cipher text is: {received_server_message}\nAnd the message is: {decrypt_response}")

    if decrypt_response == 'Bye' or decrypt_response == 'bye':
        connectionSocket.close()
        connection = False
