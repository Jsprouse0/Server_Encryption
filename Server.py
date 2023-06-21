import socket                                                                   # Robert Gleason and Jacob Sprouse


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

    while True:
        print("Waiting for connection.....")

        # addr_port is a tuple that contains both the address and the port number
        # clientSocket is the communication variable between host and port
        client_socket, addr_port = server_socket.accept()

        print("\nGot a connection from " + str(addr_port))

        received_bytes = client_socket.recv(1024)

        received_message = bytes.decode(received_bytes)

        print(received_message)

        # Response
        message = 'hi'

        message_encode = message.encode()

        client_socket.send(message_encode)

        client_socket.close()