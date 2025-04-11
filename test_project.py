import os
from project import (
    generate_aes_key,
    generate_rsa_key,
    load_key,
    aes_encrypt_file,
    aes_decrypt_file,
    rsa_encrypt_file,
    rsa_decrypt_file,
)


# Helper function for setup (runs before each test)
def setup_files():
    """Setup initial files and variables before each test"""
    password = b"TestPassword"
    filename = "test_key"
    input_file = "test_input.txt"
    output_file = "test_output.txt"
    key_file = "test_key.key"
    test_text = b"Hello, this is a test file content!"

    # Create a test input file
    with open(input_file, "wb") as f:
        f.write(test_text)

    return password, filename, input_file, output_file, key_file, test_text


# Helper function for teardown (cleanup)
def teardown_files():
    """Clean up after each test by deleting generated files"""
    for file in [
        "test_input.txt",
        "test_output.txt",
        "test_key.key",
        "test_decrypted.txt",
        "test_decrypted_rsa.txt",
        "test_key_rsa_private.pem",
        "test_key_rsa_public.pem",
    ]:
        if os.path.exists(file):
            os.remove(file)


def test_generate_aes_key():
    password, filename, _, _, _, _ = setup_files()

    # Test AES key generation
    generate_aes_key(password, filename)

    # Ensure the key file is created
    assert os.path.exists(f"{filename}.key"), "AES key file was not created"

    teardown_files()


def test_generate_rsa_key():
    password, filename, _, _, _, _ = setup_files()

    # Test RSA key generation
    generate_rsa_key(password, filename)

    # Ensure the RSA key files are created
    assert os.path.exists(
        f"{filename}_rsa_private.pem"
    ), "RSA private key was not created"
    assert os.path.exists(
        f"{filename}_rsa_public.pem"
    ), "RSA public key was not created"

    teardown_files()


def test_load_key():
    password, filename, _, _, key_file, _ = setup_files()

    # Generate AES key and load it
    generate_aes_key(password, filename)
    aes_key = load_key(key_file, password)
    assert len(aes_key) == 32, "AES key length is incorrect"

    # Generate RSA keys and load private key
    generate_rsa_key(password, filename)
    private_key = load_key(f"{filename}_rsa_private.pem", password)
    assert private_key is not None, "Private key was not loaded"

    teardown_files()


def aes_encrypt_decrypt_file():
    password, filename, input_file, output_file, key_file, test_text = setup_files()

    # Generate AES key and load it
    generate_aes_key(password, filename)
    aes_key = load_key(key_file, password)

    # Encrypt the file
    aes_encrypt_file(aes_key, input_file, output_file)
    assert os.path.exists(output_file), "Encrypted file was not created"

    # Decrypt the file and verify content
    aes_decrypt_file(aes_key, output_file, "test_decrypted.txt")
    with open("test_decrypted.txt", "rb") as f:
        decrypted_content = f.read()
    assert (
        decrypted_content == test_text
    ), "Decrypted content does not match the original"

    teardown_files()


def rsa_encrypt_decrypt_file():
    password, filename, input_file, output_file, key_file, test_text = setup_files()

    # Generate RSA keys and load them
    generate_rsa_key(password, filename)
    public_key = load_key(f"{filename}_rsa_public.pem", password)
    private_key = load_key(f"{filename}_rsa_private.pem", password)

    # Encrypt the file
    rsa_encrypt_file(public_key, input_file, output_file)
    assert os.path.exists(output_file), "Encrypted file was not created"

    # Decrypt the file and verify content
    rsa_decrypt_file(private_key, output_file, "test_decrypted_rsa.txt")
    with open("test_decrypted_rsa.txt", "rb") as f:
        decrypted_content = f.read()
    assert (
        decrypted_content == test_text
    ), "Decrypted content does not match the original"

    teardown_files()


def test_aes_encrypt_file():
    """
    Test case that ensures AES encryption works correctly by calling the
    'test_rsa_encrypt_decrypt_file' function.
    """
    # Call the aes_encrypt_decrypt_file to ensure both encryption and decryption are tested
    aes_encrypt_decrypt_file()


def test_aes_decrypt_file():
    """
    Test case that ensures AES decryption works correctly by calling the
    'aes_encrypt_decrypt_file' function.
    """
    # Call the aes_encrypt_decrypt_file to ensure both encryption and decryption are tested
    aes_encrypt_decrypt_file()


def test_rsa_encrypt_file():
    """
    Test case that ensures RSA encryption works correctly by calling the
    'test_rsa_encrypt_decrypt_file' function.
    """
    # Call the rsa_encrypt_decrypt_file to ensure both encryption and decryption are tested
    rsa_encrypt_decrypt_file()


def test_rsa_decrypt_file():
    """
    Test case that ensures RSA decryption works correctly by calling the
    'test_rsa_encrypt_decrypt_file' function.
    """
    # Call the rsa_encrypt_decrypt_file to ensure both encryption and decryption are tested
    rsa_encrypt_decrypt_file()


if __name__ == "__main__":
    test_generate_aes_key()
    test_generate_rsa_key()
    test_load_key()
    test_aes_encrypt_file()
    test_aes_decrypt_file()
    test_rsa_encrypt_file()
    test_rsa_decrypt_file()
    print("All tests passed!")
