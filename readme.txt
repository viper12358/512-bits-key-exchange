The Server will generate a 512 bits long prime number and exchange with the Client
1. The Client with login with their usename and password. These will be encrypted and sent to the Server
2. The Server will generate a 512 bits safe prime number and it's prime root g
3. The Client will create a random salt s and then generate hash value x which is H(s||p) 
4. 