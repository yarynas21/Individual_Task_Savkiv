from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image
import os

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def extract_signature_from_image(image_path, sig_length):
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

    raise ValueError("Підпис не знайдено у зображенні.")

def main():
    if not os.path.exists("keys/public_key.pem"):
        raise FileNotFoundError("Спочатку згенеруйте ключі через generate_keys.py!")

    public_key = load_public_key("keys/public_key.pem")

    original_folder = "images/original_images"
    signed_folder = "images/signed_images"

    for filename in os.listdir(original_folder):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
            original_path = os.path.join(original_folder, filename)
            signed_path = os.path.join(signed_folder, filename)

            if not os.path.exists(signed_path):
                print(f"⚠️ Підписане зображення для {filename} не знайдено, пропускаємо.")
                continue

            with open(original_path, "rb") as img_file:
                image_data = img_file.read()

            try:
                signature = extract_signature_from_image(signed_path, 512)
                print(f"🔍 Перевірка підпису для {filename}...")
                print(f"🔍 Підпис: {signature.hex()}")
                public_key.verify(
                    signature,
                    image_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"✅ Підпис на {filename} валідний.")
            except Exception as e:
                print(f"❌ Підпис на {filename} недійсний: {e}")

if __name__ == "__main__":
    main()