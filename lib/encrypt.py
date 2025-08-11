import os
from typing import Optional, Literal
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
from nacl.utils import random as nacl_random
from argon2.low_level import hash_secret_raw, Type

# Constants
MODE_PASSWORD_ONLY: int = 0x00
MODE_PASSWORD_PLUS_KEY: int = 0x01
MODE_KEY_ONLY: int = 0x02
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 24  # XChaCha20 uses 192-bit nonces


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_SIZE,
        type=Type.ID
    )

def encrypt_file(input_bytes: bytes, output_path: str,
                 mode: Literal[0x00, 0x01, 0x02],
                 password: Optional[str] = None,
                 usb_key: Optional[bytes] = None) -> None:
    """
    Encrypts and writes a file.
    mode:
        0x00 = password only
        0x01 = password + key
        0x02 = key only
    """
    if mode == MODE_PASSWORD_ONLY:
        if not password:
            raise ValueError("Password is required for password-only mode")
        salt = os.urandom(SALT_SIZE)
        key = derive_key_from_password(password, salt)
        header = bytes([MODE_PASSWORD_ONLY]) + salt

    elif mode == MODE_PASSWORD_PLUS_KEY:
        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        salt = os.urandom(SALT_SIZE)
        pw_key = derive_key_from_password(password, salt)
        key = bytes(a ^ b for a, b in zip(pw_key, usb_key))  # Combine securely
        header = bytes([MODE_PASSWORD_PLUS_KEY]) + salt

    elif mode == MODE_KEY_ONLY:
        if not usb_key:
            raise ValueError("Key required for key-only mode")
        key = usb_key
        header = bytes([MODE_KEY_ONLY])

    else:
        raise ValueError(f"Invalid mode: {mode}")

    nonce = nacl_random(NONCE_SIZE)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        input_bytes,
        header,  # Associated Data (binds mode/salt to ciphertext)
        nonce,
        key
    )

    with open(output_path, "wb") as f:
        f.write(header + nonce + ciphertext)


def decrypt_file(input_path: str,
                 password: Optional[str] = None,
                 usb_key: Optional[bytes] = None) -> bytes:
    """Decrypts and returns the file contents."""
    with open(input_path, "rb") as f:
        data = f.read()

    mode = data[0]

    if mode == MODE_PASSWORD_ONLY:
        salt = data[1:1+SALT_SIZE]
        nonce = data[1+SALT_SIZE:1+SALT_SIZE+NONCE_SIZE]
        ciphertext = data[1+SALT_SIZE+NONCE_SIZE:]
        if not password:
            raise ValueError("Password is required for password-only mode")
        key = derive_key_from_password(password, salt)

    elif mode == MODE_PASSWORD_PLUS_KEY:
        salt = data[1:1+SALT_SIZE]
        nonce = data[1+SALT_SIZE:1+SALT_SIZE+NONCE_SIZE]
        ciphertext = data[1+SALT_SIZE+NONCE_SIZE:]
        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        pw_key = derive_key_from_password(password, salt)
        key = bytes(a ^ b for a, b in zip(pw_key, usb_key))

    elif mode == MODE_KEY_ONLY:
        nonce = data[1:1+NONCE_SIZE]
        ciphertext = data[1+NONCE_SIZE:]
        if not usb_key:
            raise ValueError("Key required for key-only mode")
        key = usb_key

    else:
        raise ValueError(f"Invalid mode: {mode}")

    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, data[:1+SALT_SIZE if mode != MODE_KEY_ONLY else 1], nonce, key)

def test_all_modes():
    test_data = b"Secret text for PangCrypter!"
    usb_key = os.urandom(KEY_SIZE)
    password = "CorrectHorseBatteryStaple"

    # Mode 0: Password only
    encrypt_file(test_data, "test_pw.enc", MODE_PASSWORD_ONLY, password=password)
    assert decrypt_file("test_pw.enc", password=password) == test_data

    # Mode 1: Password + key
    encrypt_file(test_data, "test_pw_key.enc", MODE_PASSWORD_PLUS_KEY, password=password, usb_key=usb_key)
    assert decrypt_file("test_pw_key.enc", password=password, usb_key=usb_key) == test_data

    # Mode 2: Key only
    encrypt_file(test_data, "test_key.enc", MODE_KEY_ONLY, usb_key=usb_key)
    assert decrypt_file("test_key.enc", usb_key=usb_key) == test_data

if __name__ == "__main__":
    test_all_modes()
    print("Encryption and decryption tests completed successfully.")