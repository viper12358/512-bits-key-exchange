""" 

IMPORTANT:
There is a known error where when value B is computed, the value is too large and hence
can't be convert to 64 bytes endian format. The program will terminate with OverFlowError
In that case please try and run the program again.

"""
import socket
import os
import random
import math
import sympy
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
import sys
from getpass import getpass


HOST = '192.168.0.1'                                                                                                  
PORT = 31802

#Registeration Function

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    # print("Registration step started")

    # Prompt user for username I
    print("Please enter a username: ")
    I = sys.stdin.readline()
    I_bytes = I.encode('utf-8')                     # encode it as bytes, and record the length
    I_length = len(I_bytes).to_bytes(4, 'big')      # convert store the length in a 4 byte array in big-endian
    client_data = I_length + I_bytes                # client data to be sent
    print("Client: Sending username: ", I)


    # Prompt user for password p
    print("Please enter a password")
    password = getpass()                                   # It's a good practice to hide the password while typing
    p_bytes = password.encode('utf-8')
    p_length = len(p_bytes).to_bytes(4, 'big')
    p_data = p_length + p_bytes
    # print("Username and password registered")


    # Generating random salt s
    # print("Client generating random Salt s...")
    salt = secrets.token_bytes(16)
    # print("Salt s is: ", salt)

    # Now we connect to the server
    conn.connect((HOST, PORT))

    #get N and g

    print("Get safe prime N and prime root g from Server...")
    N = int.from_bytes(conn.recv(64), 'big')
    g = int.from_bytes(conn.recv(64), 'big')
    # print("Safe prime N: ", N)
    # print("Prime root g: ", g)


    # Generate hash value x which is H(s||p)
    # print("Generating hash value x...")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)     
    digest.update(p_bytes)
    x = digest.finalize()
    x = int.from_bytes(x,sys.byteorder)
    # print("Hash value x generated: ", x)

    # Calculating value v which is g^x mod N
    # print("Calculating value v....")
    v = pow(g,x,N)
    # print("Value of v is: " + str(v))
    # print("Converting v to byte...")
    v_data = v.to_bytes(64, 'big')
    # print("V converted, the value is: ", v)


    # Creating byte r
    r = bytes('r', 'utf-8')
    # print("Byte 'r' generated, the value is: ", r)

    data = r + client_data + salt + v_data

    # print("Sending data ('r', |I|, I, s, v) to the server....")
    print("Client: Sending 'r'= ", r.hex().lstrip("0x"))
    print("Client: Sending |I| = ", I_length.hex().lstrip("0x"))
    print("Client: Sending I = ", I_bytes.hex().lstrip("0x"))
    print("Client: Sending s = ", salt.hex().lstrip("0x"))
    print("Client: Sending v = ", hex(v).lstrip("0x"))

    conn.send(data)

    server_response = conn.recv(1024)
    print((server_response.decode('utf-8')))
    print("Client: Registration successful.")

    # dispose of x
    # print("Disposing x...")
    x = 0


# This might cause a problem on a network infrastructure or if there is more than 1 client 
# but I can't quite figure out how to close the socket then reconnect it normally
# Hence I simply create a new socket which listen from the same source. 
# New addr is pretty much the previous address

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as protoConn:

    # print("\n")
    # print("Protocol step")
    # print("Connecting to Server ...")

    protoConn.connect((HOST, PORT))
    
    # print("Getting safe prime N and prime root g from Server...")
    N = int.from_bytes(protoConn.recv(64), 'big')
    g = int.from_bytes(protoConn.recv(64), 'big')
    # print("Safe prime N: ", N)
    # print("Primitive root g: ", g)


    # Generating single byte 'p'
    # Please don't confuse this with the p = password above
    # print("Client is generating single byte 'p'...")
    p = bytes('p', 'utf-8')
    # print("Byte p generated: ", p)


    # Generate random number 0<= a <= N-1 
    # print("Generating random number a...")
    a = secrets.randbelow(N-1)
    # print("Calculating A...")
    A = pow(g,a,N)
    # print("A calculated: ", A)

    # convert A to 64 byte big endian format
    # print("Converting A to bytes...")
    A_bytes = A.to_bytes(64, 'big')
    # print("A successfully converted: ", A_bytes)
    
    # sending tuple of data to server
    data = p + p_length + p_bytes + A_bytes
    print("Client: Sending ('p', |I|, I, A) to the server = ", data)
    protoConn.send(data)


    # getting salt s from server
    # print("Receving Salt s from Server...")
    salt = protoConn.recv(16)
    # print("Salt s is: ", salt)
    # getting B from server
    # print("Receving value B from Server...")
    B = int.from_bytes(protoConn.recv(64), 'big')
    B_Bytes = B.to_bytes(64, 'big')
    # print("Value of B is: ", B)

    
    # u = H(A||B) mod N
    # print("Generating hash value u = H(A||B) mod N")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(A_bytes)
    digest.update(B_Bytes)
    u = digest.finalize()
    u = int.from_bytes(u,sys.byteorder)
    u = u % N
    # print("Hash value u generated: ",u)

    
    # k = H(N||g) mod N
    # print("Generating hash value k = H(N||g)")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(N.to_bytes(64, 'big'))
    digest.update(g.to_bytes(64, 'big'))
    k = digest.finalize()
    k = int.from_bytes(k,sys.byteorder)
    # print("Hash value k generated: ", k)


    # Recalculating x
    # x = H(S||p)
    # print("Generating hash value x = H(S||p)")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(p_bytes)
    x = digest.finalize()
    x = int.from_bytes(x,sys.byteorder)
    # print("Hash value x generated: ", x)
    

    # print("Calculating Client Key....")
    clientKey = pow((B-k*v),(a+u*x),N)
    # print("Client Key generated: ", clientKey)
    K_clientBytes = clientKey.to_bytes(64, 'big')


    # print("Generating Hash value M1 = (A||B||K_Client)")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(A_bytes)
    digest.update(B_Bytes)
    digest.update(K_clientBytes)
    M1_bytes = digest.finalize()
    M1 = int.from_bytes(M1_bytes,'big')
    # print("Hash value M1 generated: ", M1)

    # convert M1 to 64 bytes big Endian format
    # send it to server
    # print("Client: Sending M1")
    M1_bytes = M1.to_bytes(64, 'big')
    protoConn.send(M1_bytes)
    
    print("Client: Sending M1 = ", hex(M1).lstrip("0x"))

    # getting M2 hash value from the server
    M2 = int.from_bytes(protoConn.recv(64), 'big')
    # convert M2 to 64 bytes big Endian format
    M2_bytes = M2.to_bytes(64, 'big')
    print("M2 received from server: ", M2)

    
    # Generate final hash value H(A||M1||K_client)
    # print("Generating final hash value H(A||M1||K_client)...")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(A_bytes)
    digest.update(M1_bytes)
    digest.update(K_clientBytes)
    finalHash = digest.finalize()
    clientHash = int.from_bytes(finalHash,'big')
    # print("final hash value generated: ", clientHash)

    # final check point to establish secured connection:
    if(M2 == clientHash):
        print("Client: Negotiation successful.")

    else:
        print("Hash value didn't match. Something is wrong, please abort connection!")