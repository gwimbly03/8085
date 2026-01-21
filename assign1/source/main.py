import argparse
import os
import struct
from PIL import Image

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode(),
        salt,
        dkLen=32,               # AES-256
        count=200_000,
        hmac_hash_module=SHA256
    )

def encrypt(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return salt + cipher.iv + ciphertext


def decrypt(enc_data: bytes, password: str) -> bytes:
    salt = enc_data[:16]
    iv = enc_data[16:32]
    ciphertext = enc_data[32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)



def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)




def encode_png(cover_png, secret_file, output_png, password):
    img = Image.open(cover_png)

    if img.format != "PNG":
        raise ValueError("Cover image must be a PNG file")

    pixels = list(img.getdata())

    with open(secret_file, "rb") as f:
        raw_data = f.read()

    if not raw_data:
        raise ValueError("Secret file is empty")

    encrypted_data = encrypt(raw_data, password)
    filename = os.path.basename(secret_file).encode("utf-8")

    # Payload structure:
    # [4 bytes encrypted length][2 bytes filename length][filename][encrypted data]
    payload = (
        struct.pack(">I", len(encrypted_data)) +
        struct.pack(">H", len(filename)) +
        filename +
        encrypted_data
    )

    bits = list(bytes_to_bits(payload))

    capacity_bits = len(pixels) * 3
    capacity_bytes = capacity_bits // 8

    if len(payload) > capacity_bytes:
        raise ValueError("File too large for the chosen image")

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        pixel = list(pixel)
        for c in range(3):  # R, G, B only
            if bit_idx < len(bits):
                pixel[c] = (pixel[c] & ~1) | bits[bit_idx]
                bit_idx += 1
        new_pixels.append(tuple(pixel))

    img.putdata(new_pixels)
    img.save(output_png, "PNG")

    print("[+] Encoding complete")
    print(f"[+] Output image: {output_png}")



def decode_png(stego_png, password, output_dir):
    img = Image.open(stego_png)
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for c in range(3):
            bits.append(pixel[c] & 1)

    data = bits_to_bytes(bits)

    enc_len = struct.unpack(">I", data[:4])[0]
    name_len = struct.unpack(">H", data[4:6])[0]

    name_start = 6
    name_end = name_start + name_len

    filename = data[name_start:name_end].decode("utf-8")
    encrypted_data = data[name_end:name_end + enc_len]

    decrypted = decrypt(encrypted_data, password)

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "wb") as f:
        f.write(decrypted)

    print("[+] Decoding complete")
    print(f"[+] Extracted file: {output_path}")




def main():
    parser = argparse.ArgumentParser(
        description="PNG LSB Steganography Tool with AES-256 Encryption"
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    enc = subparsers.add_parser("encode", help="Encode a file into a PNG")
    enc.add_argument("-i", "--image", required=True, help="Cover PNG image")
    enc.add_argument("-f", "--file", required=True, help="File to hide")
    enc.add_argument("-o", "--output", required=True, help="Output PNG")
    enc.add_argument("-k", "--key", required=True, help="Encryption key")

    dec = subparsers.add_parser("decode", help="Decode a file from a PNG")
    dec.add_argument("-i", "--image", required=True, help="Stego PNG image")
    dec.add_argument("-o", "--output", default=".", help="Output directory")
    dec.add_argument("-k", "--key", required=True, help="Encryption key")

    args = parser.parse_args()

    try:
        if args.mode == "encode":
            encode_png(args.image, args.file, args.output, args.key)
        elif args.mode == "decode":
            decode_png(args.image, args.key, args.output)
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
