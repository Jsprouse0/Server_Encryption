import socket                                                                       # Robert Gleason and Jacob Sprouse
from Server import Socket

# create socket object
connectionSocket = Socket.server()
host = Socket.host()
port = Socket.port()
connection = True


while connection:
    connectionSocket.connect((host, port))

    message = 'hello I am the client'

    message_encode = message.encode()

    connectionSocket.send(message_encode)

    received_bytes = connectionSocket.recv(1024)

    received_message = bytes.decode(received_bytes)

    print(received_message)
    connection == False

connectionSocket.close()
