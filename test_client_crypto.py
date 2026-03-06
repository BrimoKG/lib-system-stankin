import requests
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 1. SETUP: Client generates its own pair of keys (Private and Public)
print("--- Step 1: Client generating keys ---")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export Public Key to PEM format to send to the server
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# 2. SIGNING: Client creates a message and signs it
message = "I approve this transaction for Book ID 101"
print(f"--- Step 2: Signing message: '{message}' ---")

signature = private_key.sign(
    message.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
signature_b64 = base64.b64encode(signature).decode()

# 3. COMMUNICATION: Send the message, signature, and public key to the server
payload = {
    "message": message,
    "signature": signature_b64,
    "public_key": public_key_pem
}

# --- THE TAMPER TEST ---
# Change the message AFTER it was signed, but BEFORE sending it to the server
#De-comment this part for test only!!!!:)

#payload["message"] = "I approve this transaction for Book ID 999" 
#print(f"--- ATTACK: Message changed to: '{payload['message']}' ---")

#4. Send to Server
print("--- Step 3: Sending to Server for verification ---")
url = "http://127.0.0.1:8000/crypto/verify-client"
response = requests.post(url, json=payload)

print(f"Server Response: {response.status_code}")
print(response.json())
