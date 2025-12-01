import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

# Add current dir to path
sys.path.append(os.getcwd())

from pki import issue_certificate
from user_keys import generate_user_keypair
from secure_messaging import send_secure_message, receive_secure_message

def create_csr(private_key, cn):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)

def test_secure_messaging():
    # 1. Create Sender Identity
    print("Creating Sender...")
    sender_priv, sender_pub = generate_user_keypair()
    sender_csr = create_csr(sender_priv, "SenderUser")
    sender_cert_pem = issue_certificate("SenderUser", sender_csr)

    sender = {
        "private_key": sender_priv,
        "cert": sender_cert_pem
    }

    # 2. Create Receiver Identity
    print("Creating Receiver...")
    receiver_priv, receiver_pub = generate_user_keypair()
    receiver_csr = create_csr(receiver_priv, "ReceiverUser")
    receiver_cert_pem = issue_certificate("ReceiverUser", receiver_csr)
    
    receiver_arg = {
        "private_key": receiver_priv
    }

    # 3. Send Message
    print("Sending message...")
    msg = "Hola, este es un mensaje secreto."
    payload = send_secure_message(sender, receiver_cert_pem, msg)
    print("Payload keys:", payload.keys())

    # 4. Receive Message
    print("Receiving message...")
    plaintext = receive_secure_message(receiver_arg, payload)
    print("Decrypted:", plaintext)

    assert plaintext == msg
    print("SUCCESS: Message verified correctly.")

if __name__ == "__main__":
    try:
        test_secure_messaging()
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
