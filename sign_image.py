"""Python script to sign images with a private key and embed the signature in the image file."""
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image

def load_private_key(path):
    """Loads the private key from a file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def sign_data(private_key, data):
    """Signs the given data using the private key."""
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def embed_signature_in_image(image_path, signature, output_path):
    """
    Embeds a digital signature into an image using LSB (Least Significant Bit) in the red channel.
    Args:
        image_path (str): Path to the input image.
        signature (bytes): Digital signature in bytes.
        output_path (str): Path to save the signed image.
    Note:
        The signature is converted to bits and embedded into the least significant bits
        of red pixels. Only lossless formats like PNG are supported; others may corrupt
        the signature.
    """
    img = Image.open(image_path)
    exif_data = img.info.get('exif')

    pixels = img.load()
    sig_bits = ''.join(f"{byte:08b}" for byte in signature)
    idx = 0

    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(sig_bits):
                if exif_data:
                    img.save(output_path, exif=exif_data)
                else:
                    img.save(output_path)
                return
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(sig_bits[idx])
            idx += 1
            pixels[x, y] = (r, g, b)

    if exif_data:
        img.save(output_path, exif=exif_data)
    else:
        img.save(output_path)

def main():
    """Main function to sign images."""
    if not os.path.exists("keys/private_key.pem"):
        raise FileNotFoundError("Please generate keys first using generate_keys.py!")

    private_key = load_private_key("keys/private_key.pem")

    input_folder = "images/original_images"
    output_folder = "images/signed_images"

    os.makedirs(output_folder, exist_ok=True)

    for filename in os.listdir(input_folder):
        if filename.lower().endswith(('.png')):
            input_path = os.path.join(input_folder, filename)
            output_path = os.path.join(output_folder, filename)

            with open(input_path, "rb") as img_file:
                image_data = img_file.read()

            signature = sign_data(private_key, image_data)
            embed_signature_in_image(input_path, signature, output_path)
            print(f"✅ Image {filename} has been signed and saved to {output_path}")

if __name__ == "__main__":
    main()
