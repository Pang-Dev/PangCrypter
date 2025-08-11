import os
import hashlib

KEY_SIZE = 32
KEY_FOLDER = ".pangcrypt_keys"

def get_drive_root_path(drive_name: str) -> str:
    """
    Returns the root path of the drive.
    Example: if drive_name is '/media/usb_drive', returns that path.
    Modify this if your environment uses different mount points.
    """
    # This assumes drive_name is a path (adjust if drive_name is a device name)
    return drive_name

def generate_secure_key() -> bytes:
    """Generate a secure random 32-byte key."""
    return os.urandom(KEY_SIZE)

def get_key_path(drive_root: str, filename: str) -> str:
    """Returns the full path to the key file inside the hidden folder."""
    folder = os.path.join(drive_root, KEY_FOLDER)
    os.makedirs(folder, exist_ok=True)

    # Make hidden on Windows
    if os.name == "nt":
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            attrs = ctypes.windll.kernel32.GetFileAttributesW(folder)
            if attrs != -1 and not (attrs & FILE_ATTRIBUTE_HIDDEN):
                ctypes.windll.kernel32.SetFileAttributesW(folder, attrs | FILE_ATTRIBUTE_HIDDEN)
        except Exception as e:
            print(f"Warning: Could not hide folder {folder}: {e}")

    key_file = f"{filename}_KEY.bin"
    return os.path.join(folder, key_file)

def create_or_load_key(drive_name: str, filename: str) -> tuple[bytes, bytes]:
    """
    Generate a secure key linked to the drive id or load existing.
    Uses a hash of the drive_name as a simple drive ID binding.
    """
    drive_root = get_drive_root_path(drive_name)
    key_path = get_key_path(drive_root, filename)

    if os.path.exists(key_path):
        # Load existing key
        with open(key_path, "rb") as f:
            return (f.read(), None)

    # Generate new key linked to drive's unique id
    # Simple binding: derive a key by hashing the drive_name + random bytes
    drive_id = hashlib.sha256(drive_name.encode('utf-8')).digest()

    random_key = generate_secure_key()

    # Combine drive_id and random_key securely (XOR)
    combined_key = bytes(a ^ b for a, b in zip(random_key, drive_id[:KEY_SIZE]))

    # Save combined key
    with open(key_path, "wb") as f:
        f.write(combined_key)

    return combined_key, random_key

def load_key_for_decrypt(drive_name: str, filename: str) -> bytes:
    drive_root = get_drive_root_path(drive_name)
    key_path = get_key_path(drive_root, filename)

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found on drive: {key_path}")

    with open(key_path, "rb") as f:
        combined_key = f.read()

    drive_id = hashlib.sha256(drive_name.encode("utf-8")).digest()
    random_key = bytes(a ^ b for a, b in zip(combined_key, drive_id[:KEY_SIZE]))
    return random_key


if __name__ == "__main__":
    # Example usage:
    drive = "F:/"
    filename = "mysecretfile"
    key = create_or_load_key(drive, filename)
    print(f"Key for {filename} on {drive}: {key[0].hex()}")
