SERVER ENCRYPTION: 
The server encryption uses 3 AES modes, ECB, CBC, and OFB. To run these you must download the files and run them in an IDE, I will update this to work on the command line so it is less of a hassle to show, but for now, the modes work fine and will encrypt or decrypt any of the three modes. The server also signs the 3 AES modes using RSA encryption

CLIENT ENCRYPTION:
The client uses the same 3 AES modes as the server and will send and receive messages from the server. The client will also create a private and public RSA key for signing the 3 modes.
