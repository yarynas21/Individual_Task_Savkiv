"""File for verifying the digital signature of images using LSB steganography."""
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PIL import Image

def load_public_key(path):
    """Loads the public key from a PEM file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def extract_signature_from_image(image_path, sig_length):
    """
    Extracts a digital signature embedded in an image using LSB in the red channel of pixels.
    Args:
        image_path (str): Path to the image with the embedded signature.
        sig_length (int): Length of the signature in bytes.
    Returns:
        bytes: Extracted digital signature.
    Description:
        Reads the least significant bits of red pixels row by row, assembles them into bytes,
        and stops once the required length is reached.
    Raises:
        ValueError: If there are not enough pixels to extract the full signature.
    """
    img = Image.open(image_path)
    pixels = img.load()
    bits = ""

    for y in range(img.height):
        for x in range(img.width):
            r, _, _ = pixels[x, y]
            bits += str(r & 1)
            if len(bits) >= sig_length * 8:
                bytes_arr = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
                return bytes(bytes_arr)

    raise ValueError("Signature not found in the image or too short.")

def main():
    """Main function for verifying the image signature."""
    if not os.path.exists("keys/public_key.pem"):
        raise FileNotFoundError("Please generate keys first using generate_keys.py!")

    public_key = load_public_key("keys/public_key.pem")

    original_folder = "images/original_images"
    signed_folder = "images/signed_images"

    for filename in os.listdir(original_folder):
        if filename.lower().endswith(('.png')):
            original_path = os.path.join(original_folder, filename)
            signed_path = os.path.join(signed_folder, filename)

            if not os.path.exists(signed_path):
                print(f"⚠️ Signed image for {filename} not found, skipping.")
                continue

            with open(original_path, "rb") as img_file:
                image_data = img_file.read()

            try:
                signature = extract_signature_from_image(signed_path, 512)
                print(f"🔍 Verifying signature for {filename}...")
                print(f"🔍 Signature: {signature.hex()}")
                public_key.verify(
                    signature,
                    image_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"✅ Signature for {filename} is valid.")
            except InvalidSignature:
                print(f"❌ Signature for {filename} is invalid: does not match the image content.")
            except ValueError as e:
                print(f"❌ Error extracting signature from {filename}: {e}")

if __name__ == "__main__":
    main()
