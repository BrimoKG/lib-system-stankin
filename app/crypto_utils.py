from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

# Initialize Server Keys for the lab
# In a real app, these would be saved to a file; here we generate them on startup
SERVER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

def get_server_public_key_pem():
    """Returns the server's public key in PEM format for Scenario 2"""
    return SERVER_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def sign_with_server(message: str):
    """Scenario 2: Server signs a message using its private key"""
    signature = SERVER_PRIVATE_KEY.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_client_signature(message: str, signature_b64: str, public_key_pem: str):
    """Scenario 1: Server verifies a message signed by the client"""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
