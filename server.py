import socket
import hashlib
import hmac
import ssl
from sympy import randprime, primitive_root
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000
BLOCK_SIZE = AES.block_size

def compute_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.load_verify_locations(cafile="ca.crt")  # Load CA certificate
    context.verify_mode = ssl.CERT_REQUIRED
    
    wrapped_socket = context.wrap_socket(server_socket, server_side=True)
    conn, address = wrapped_socket.accept()
    print("Secure connection from: " + str(address))
    
    try:
        client_cert_bin = conn.getpeercert(binary_form=True)
        client_cert = x509.load_der_x509_certificate(client_cert_bin, default_backend())
        client_public_key = client_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if not client_cert:
            raise ValueError("Client certificate verification failed.")

        p = randprime(2**127, 2**128)
        g = primitive_root(p)
        alpha = randint(1, p-1)
        h1 = pow(g, alpha, p)
        conn.sendall(f"{p},{g},{h1}".encode())

        h2 = int(conn.recv(2048).decode())

        message = f"{p},{g},{h1},{h2}".encode()
        hash_value = SHA256.new(message)
        server_key = RSA.import_key(open("server.key").read())
        signature = pkcs1_15.new(server_key).sign(hash_value)
        conn.send(signature)

        client_signature = conn.recv(2048)
        hash_client = SHA256.new(message)
        pkcs1_15.new(RSA.import_key(client_public_key)).verify(hash_client, client_signature)

        print("RSA and DH Key Exchange Complete. Proceed with AES communication.")
        K = pow(h2, alpha, p)
        aes_key = K.to_bytes(16, 'big')
        iv_msg = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv_msg)
        msg = b"Hello, this is a secure message."
        encrypted_msg = cipher.encrypt(pad(msg, BLOCK_SIZE))
        hmac_value = compute_hmac(aes_key, encrypted_msg)
        conn.send(encrypted_msg + iv_msg + hmac_value)

        # Receive encrypted message from client
        received_data = conn.recv(1040 + 32)
        received_encrypted_msg = received_data[:-48]
        received_iv = received_data[-48:-32]
        received_hmac = received_data[-32:]

        # Verify and decrypt the message
        if hmac.compare_digest(compute_hmac(aes_key, received_encrypted_msg), received_hmac):
            cipher = AES.new(aes_key, AES.MODE_CBC, received_iv)
            decrypted_msg = unpad(cipher.decrypt(received_encrypted_msg), BLOCK_SIZE)
            response = f"Received and decrypted client's message: {decrypted_msg.decode()}"
        else:
            response = "HMAC verification failed."
        conn.send(response.encode())

    except Exception as e:
        print(f"An error occurred: {e}")

    conn.close()

if __name__ == '__main__':
    server_program()
