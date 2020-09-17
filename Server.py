""" 
USAGE: python Server.py - Run this BEFORE running the Client

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

HOST = '192.168.0.1'                                                                                                     # Standard loopback interface address (localhost)
PORT = 31802   

# hard core for easy testing
# N = 10867589447495203363205359740903224358555932311659409641688582771318101899581978187535140262819906001236028552415592694623494539337717721981223907824759547
# g = 29

# Finding safe Prime:
# stop condition
prime = False
# process to generate prime number:
while prime == False:
# make it odd so we don't have to deal with even number got randomly generated
    q = secrets.randbits(511) | 1
    # test prime for q
    if sympy.isprime(q) == True:
        n = 2*q+1
        # test prime for n
        if sympy.isprime(n) == True:
            N = n
            break
        else:
            prime = False
    else:
        prime = False


# A "safe prime" is an integer p which is such that both p and (p−1)/2 are prime. 
# Since we generated a "safe prime", then there are only two prime factors of p−1: 
# these are 2, and (p−1)/2. The test for primitive roots becomes:
# Finding primitive root of such safe Prime:
# Testing with 2 prime factors
found = False
while found == False:
    rootsCandidate = secrets.randbelow(19)+1   
    if pow(rootsCandidate,2,N) != 1:
        if pow(rootsCandidate,q,N) != 1:
            g = rootsCandidate
            found = True
        else:
            found = False
    else:
        found = False       


print("safe prime: ", N)
print("primitive root: ", g)

N_bytes = N.to_bytes(64, 'big')     # encode to 64 bytes big endian format
g_bytes = g.to_bytes(64, 'big')     # encode to 64 bytes big endian format


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    
    s.bind((HOST, PORT))
    s.listen()
    # print('Server listening...')
    conn, addr = s.accept()
    with conn:
        # print("Registration step")

        conn.send(N_bytes)
        print("Server: Sending N = ", hex(N).lstrip("0x"))               # hex it as per requirement
        conn.send(g_bytes)
        print("Server: Sending g = ", hex(g).lstrip("0x"))               # hex it as per requirement


        # print("Recieve tuple from Client: (‘r’, |I|, I, s, v)")
        # print("Receiving byte 'r' from Client...")
        r = conn.recv(1)
        # print("Value of r is: ", r)

        
        # print("Recieving Client data (|I| and I) from Client...")
        clientlength = int.from_bytes(conn.recv(4), 'big')
        uname = conn.recv(clientlength)
        user = uname.decode('utf-8')
        user = user.strip('\n')
        # print("|I| is: ", clientlength)
        # print("Value of I is: ", user)


        #Get Salt s
        # print("Receiving Salt s from Client...")
        salt = conn.recv(16)
        # print("Value of Salt s is: ", salt)

        #Get v
        # print("Receiving v  from Client...")
        v = int.from_bytes(conn.recv(64), 'big')
        # print("v is: ", v)

        # print("I, v , s will be stored for future used")
        print("Server: Registration successful.")
        

    # This might cause a problem on a network infrastructure or if there is more than 1 client 
    # but I can't quite figure out how to close the socket then reconnect it normally
    # Hence I simply create a new socket which listen from the same source. 
    # New addr is pretty much the previous address
    s.listen()
    protoConn, newAddr = s.accept()

    # print("\n")
    # print("Protocol step")
    with protoConn:
        
        # print("Sending safe prime and primitive root to Client again")
        protoConn.send(N_bytes)
        print("Serer: Sending N = ", hex(N).lstrip("0x"))
        protoConn.send(g_bytes)
        print("Server: Sending g = ", hex(g).lstrip("0x"))


        # Get the tuple (‘p’, |I|, I, A) from Client
        # print("Recieve tuple: (‘p’, |I|, I, A)")


        # Get p
        # print("Receiving 'p' from Client...")
        p_bytes = protoConn.recv(1)
        p = p_bytes.decode('utf-8')
        # print("Value of 'p' is: ", p)


        # Get Client data
        # print("Recieving Client data (|I| and I) from Client...")
        clientlength = int.from_bytes(protoConn.recv(4), 'big')
        uname = protoConn.recv(clientlength)
        user = uname.decode('utf-8')
        user = user.strip('\n')
        # print("Value of I is: ", user)


        #Get A
        # print("Receiving A from Client...")
        A = int.from_bytes(protoConn.recv(64), 'big')               # all number is 64 byte big endian format
        A_bytes = A.to_bytes(64, 'big')
        # print("Value of A is: ", A)


        # generate hash value k = H(N||g)
        # print("Generating hash k ...")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(N_bytes)
        digest.update(g_bytes)
        k = digest.finalize()
        k = int.from_bytes(k,sys.byteorder)
        # print("Value of k is: ", k)


        # generating B which is = (k*v mod N)  * (g^b mod N)
        # print("Generating B ...")
        b = secrets.randbelow(N-1)
        B = (k*v) % N + pow(g,b,N)
        # print("B is: ", B)

        # Convert B to bytes
        # Note: There will be rare cases where B is too big and can't be converted
        # which result in overFlowError, in that case please run the program again
        # print("Converting B to bytes")
        try:
            B_bytes = B.to_bytes(64, 'big')                             # all number is 64 byte big endian format
        except OverflowError as error:
            print("OverflowError, please try and run the program again")

        # print("Value of B in Bytes: ", B_bytes)

        data = salt + B_bytes
        
        protoConn.send(data)
        
        print("Server: Sending s = ", salt.hex().lstrip("0x"))
        print("Server: Sending B = ", hex(B).lstrip("0x"))


        # u ≡ H(A||B) (mod N).
        # print("Generating Hash value u...")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(A_bytes)
        digest.update(B_bytes)
        u = digest.finalize()
        u = int.from_bytes(u,sys.byteorder)
        u = u % N
        # print("Value of u is: ", u)

        # we expand the original formula of Key_Server which is (Av^u)^b mod N 
        # using Modular Arithmetic properties
        server_Key = pow((A % N * pow (v,u,N)),b,N)
        K_Server_bytes =  server_Key.to_bytes(64, 'big')
        # print("Value of K_Server is: ", server_Key)

        
        # generating Hash value H(A||B||K_server)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(A_bytes)
        digest.update(B_bytes)
        digest.update(K_Server_bytes)
        H_K_Server_Bytes = digest.finalize()
        serverHash = int.from_bytes(H_K_Server_Bytes, 'big')
        # print("Hash value H(A||B||K_server): ", serverHash)


        # print("Receiving M1 from Client...")
        M1 = int.from_bytes(protoConn.recv(64), 'big')
        M1_bytes = M1.to_bytes(64, 'big')
        # print("Value of M1 is: ", M1)
        

        if (M1 == serverHash):
            # print("Hash value confirmed, safe connection channcel established")

            # Computes and sends M2 = H(A||M1||K_server).
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(A_bytes)
            digest.update(M1_bytes)
            digest.update(K_Server_bytes)
            m2bytes = digest.finalize()
            M2 = int.from_bytes(m2bytes, 'big')
            # print("Value of M2: ", M2)
            
            # Convert M2 to bytes
            m2bytes = M2.to_bytes(64, 'big')
            # print("Sending M2 to Client...")
            protoConn.send(m2bytes)
            print("Server Sending M2 = ", hex(M2).lstrip("0x"))
            print("Server: Negatiation successful.")

        else:
            print("This client is malicious. Abort")