# Encryption and Decryption System

Objective: Design and implement secure network applications using standard cryptographic libraries in Java.
Client and server side with signature verification.

## Features
- End-to-end encrypted communication between client and server
- Digital signatures for message authentication + integrity
- Secure file transfer potential
- Easy connection termination

Key systems: RSA/ECB/PKCS1Padding, 256-bit AES key, AES/CBC/PKCS5Padding, MD5 Hash, 

## Three Active Commands:
`ls` - sends a list of filenames avaliable for download.
`get` - request server to send contents of the file.
`bye` - client has no more requests the connection is closed.

### How to run?
1. Start server
2. Run client
3. Communicate using commands to interact with system
