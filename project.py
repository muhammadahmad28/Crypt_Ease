import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
import getpass


def derive_key_from_password(password: bytes, salt: bytes, length: int = 32) -> bytes:
    """Derive an AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)


def generate_aes_key(password: bytes, filename: str):
    """Generate and save an AES key, password-protected."""
    aes_key = os.urandom(32)  # AES key generation
    salt = os.urandom(16)
    derived_key = derive_key_from_password(password, salt)

    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(aes_key) + padder.finalize()
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()

    with open(f"{filename}.key", "wb") as key_file:
        key_file.write(salt + iv + encrypted_key)
    print(f"AES key saved as '{filename}.key'.")


def generate_rsa_key(password: bytes, filename: str):
    """Generate and save an RSA key pair, password-protected."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    with open(f"{filename}_rsa_private.pem", "wb") as private_file:
        private_file.write(pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(f"{filename}_rsa_public.pem", "wb") as public_file:
        public_file.write(public_pem)

    print(
        f"RSA private key saved as '{filename}_rsa_private.pem' and public key as '{filename}_rsa_public.pem'."
    )


def load_key(filename: str, password: bytes = None):
    """Load and decrypt an AES or RSA key from a file."""
    with open(filename, "rb") as key_file:
        key_data = key_file.read()

    # AES key load
    if filename.endswith(".key"):
        salt, iv, encrypted_key = key_data[:16], key_data[16:32], key_data[32:]
        derived_key = derive_key_from_password(password, salt)

        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_key = decryptor.update(encrypted_key) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        aes_key = unpadder.update(padded_key) + unpadder.finalize()
        return aes_key

    # RSA private key load
    elif filename.endswith("_rsa_private.pem"):
        private_key = serialization.load_pem_private_key(
            key_data, password=password, backend=default_backend()
        )
        return private_key

    # RSA public key load
    elif filename.endswith("_rsa_public.pem"):
        public_key = serialization.load_pem_public_key(
            key_data, backend=default_backend()
        )
        return public_key

    else:
        raise ValueError("Unsupported key file format")


def aes_encrypt_file(aes_key, input_file, output_file):
    """Encrypt a file using AES."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(iv + ciphertext)
    print(f"File encrypted and saved to {output_file}.")


def aes_decrypt_file(aes_key, input_file, output_file):
    """Decrypt a file using AES."""
    with open(input_file, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, "wb") as f:
        f.write(plaintext)
    print(f"File decrypted and saved to {output_file}.")


def rsa_encrypt_file(public_key, input_file, output_file):
    """Encrypt a file using RSA."""
    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = public_key.encrypt(
        plaintext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    with open(output_file, "wb") as f:
        f.write(ciphertext)
    print(f"File encrypted and saved to {output_file}.")


def rsa_decrypt_file(private_key, input_file, output_file):
    """Decrypt a file using RSA."""
    with open(input_file, "rb") as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    with open(output_file, "wb") as f:
        f.write(plaintext)
    print(f"File decrypted and saved to {output_file}.")


def guided_mode():
    print("Guided Mode:")
    action = input("Choose action (generate_keys(g), encrypt(e), decrypt(d)): ").strip()

    if action == "generate_keys" or action == "g":
        alg = input("Choose algorithm AES(1), RSA(2): ").strip().upper()
        filename = input("Enter the filename for saving the key: ").strip()
        password = getpass.getpass("Enter a password to protect the key: ").encode()
        confirm_password = getpass.getpass("Confirm the password: ").encode()

        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            return

        if alg == "AES" or alg == "1":
            generate_aes_key(password, filename)
        elif alg == "RSA" or alg == "2":
            generate_rsa_key(password, filename)
        else:
            print("Unsupported algorithm.")
            sys.exit()

    elif action == "encrypt" or action == "e":
        alg = input("Choose algorithm AES(1), RSA(2)): ").strip().upper()
        input_file = input("Enter the input file path: ").strip()
        output_file = input("Enter the output file path: ").strip()
        key_file = input(
            "Enter the key file path (or press Enter to generate one): "
        ).strip()

        if not key_file and (alg == "AES" or alg == "1"):
            filename = input("Enter the filename for saving the new key: ").strip()
            password = getpass.getpass("Enter a password to protect the key: ").encode()
            confirm_password = getpass.getpass("Confirm the password: ").encode()

            if password != confirm_password:
                print("Passwords do not match. Please try again.")
                return
            generate_aes_key(password, filename)
            key_file = f"{filename}.key"

        password = getpass.getpass("Enter password for the key file: ").encode()
        if alg == "AES" or alg == "1":
            aes_key = load_key(key_file, password)
            aes_encrypt_file(aes_key, input_file, output_file)
        elif alg == "RSA" or alg == "2":
            public_key = load_key(key_file, password)
            rsa_encrypt_file(public_key, input_file, output_file)

    elif action == "decrypt" or action == "d":
        input_file = input("Enter the encrypted file path: ").strip()
        output_file = input("Enter the output file path: ").strip()
        key_file = input("Enter the key file path: ").strip()
        password = getpass.getpass("Enter password for the key file: ").encode()

        if key_file.endswith(".key"):
            aes_key = load_key(key_file, password)
            aes_decrypt_file(aes_key, input_file, output_file)
        elif key_file.endswith("_rsa_private.pem"):
            private_key = load_key(key_file, password)
            rsa_decrypt_file(private_key, input_file, output_file)
        else:
            print("Unsupported key file format.")
            sys.exit()


def main():
    import sys

    if len(sys.argv) == 1:
        guided_mode()
    else:
        # Argument parsing and handling
        print("Argument Mode")
        # Will add support for arguments later


if __name__ == "__main__":
    main()
