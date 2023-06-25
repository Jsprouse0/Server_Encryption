# Robert Gleason and Jacob Sprouse
import socket
from Server import Socket
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

# create socket object
connectionSocket = Socket.server()
host = Socket.host()
port = Socket.port()

key = get_random_bytes(16)
connection = True
connectionSocket.connect((host, port))

while connection:
    # Client message
    message = input()
    message_encode = message.encode()

    # encryption key
    encrypt_cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = encrypt_cipher.encrypt(pad(message_encode, AES.block_size))
    print(ciphertext)

    # sends message across socket to server
    connectionSocket.send(ciphertext)
    connectionSocket.send(key)

    # Server Response
    received_ciphertext = connectionSocket.recv(1024)
    decrypt_cipher = AES.new(key, AES.MODE_ECB)
    decrypt_bytes = unpad(decrypt_cipher.decrypt(received_ciphertext), AES.block_size)

    received_message = bytes.decode(decrypt_bytes)

    print(f"The cipher text is {received_ciphertext} and the message is {received_message}")

    if received_message == 'Bye' or received_message == 'bye':
        connectionSocket.close()
        connection = False
