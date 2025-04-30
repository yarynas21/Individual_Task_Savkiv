"""Generation of RSA keys for signing and verifying signatures"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(private_key_path, public_key_path):
    """
    Generates an RSA key pair and saves them to files.
    Arguments:
        private_key_path (str): Path to save the private key.
        public_key_path (str): Path to save the public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
def main():
    """
    Main function for key generation.
    Creates the 'keys' folder if it does not exist and generates the keys.
    """
    os.makedirs("keys", exist_ok=True)
    generate_keys("keys/private_key.pem", "keys/public_key.pem")
    print("✅ Keys have been generated in the keys/ directory.")

if __name__ == "__main__":
    main()
