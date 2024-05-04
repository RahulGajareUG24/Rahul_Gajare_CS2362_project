import socket
import hashlib
import hmac
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from sympy import primitive_root, randprime
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 5000
BLOCK_SIZE = AES.block_size

def compute_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def client_program():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    context.load_verify_locations(cafile="ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            try:
                server_cert_bin = ssock.getpeercert(binary_form=True)
                server_cert = x509.load_der_x509_certificate(server_cert_bin, default_backend())
                server_public_key = server_cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                if not server_cert:
                    raise ValueError("Server certificate verification failed.")

                data = ssock.recv(1024).decode()
                p, g, h1 = map(int, data.split(','))

                beta = randint(1, p-1)
                h2 = pow(g, beta, p)
                ssock.send(str(h2).encode())

                message = f"{p},{g},{h1},{h2}".encode()
                hash_value = SHA256.new(message)
                client_key = RSA.import_key(open("client.key").read())
                signature = pkcs1_15.new(client_key).sign(hash_value)
                ssock.send(signature)

                server_signature = ssock.recv(1024)
                hash_server = SHA256.new(message)
                pkcs1_15.new(RSA.import_key(server_public_key)).verify(hash_server, server_signature)

                print("RSA and DH Key Exchange Complete. Ready for AES communication.")

                K = pow(h1, beta, p)
                aes_key = K.to_bytes(16, 'big')
                received_data = ssock.recv(1040 + 32)
                encrypted_msg = received_data[:-48]
                iv_msg = received_data[-48:-32]
                received_hmac = received_data[-32:]

                if not hmac.compare_digest(compute_hmac(aes_key, encrypted_msg), received_hmac):
                    raise ValueError("HMAC verification failed.")

                cipher = AES.new(aes_key, AES.MODE_CBC, iv_msg)
                decrypted_msg = unpad(cipher.decrypt(encrypted_msg), BLOCK_SIZE)
                print(f"Decrypted Message: {decrypted_msg.decode()}")

        # Choose and send an encrypted message back to server
                iv_confirm = get_random_bytes(BLOCK_SIZE)
                confirmation_msg = b"Secure response from client."
                cipher_confirm = AES.new(aes_key, AES.MODE_CBC, iv_confirm)
                encrypted_confirmation = cipher_confirm.encrypt(pad(confirmation_msg, BLOCK_SIZE))
                hmac_confirm = compute_hmac(aes_key, encrypted_confirmation)
                ssock.send(encrypted_confirmation + iv_confirm + hmac_confirm)

                response = ssock.recv(1024).decode()
                print(f"Server responded with: {response}")

            except Exception as e:
                print(f"An error occurred: {e}")

if __name__ == '__main__':
    client_program()
