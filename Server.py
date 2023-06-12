import socket

# Creates a socket object that listens
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get host name
host = socket.gethostname()

# the socket listens at port 7777 that doesn't interfere with other processes
port = 7777

# bind the socket to the port, bridge between host && port
serverSocket.bind((host, port))

# start listening
serverSocket.listen()

print("Waiting for connection.....")

# addr_port is a tuple that contains both the address and the port number
# clientSocket is the communication variable between host and port
clientSocket, addr_port = serverSocket.accept()

print("\nGot a connection from " + str(addr_port))





