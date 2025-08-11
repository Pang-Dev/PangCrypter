# PangCrypter

PangCrypter is a secure, standalone Windows executable tool for encrypting and editing files with strong AES encryption. It features a sleek dark-themed interface and advanced USB-drive-bound key management for enhanced data security.

---

## Features

- Encrypt and decrypt files using AES-256 encryption.
- Bind encryption keys to specific USB drives for hardware-tied security.
- Support for password-only, USB key-only, or password + USB key hybrid encryption modes.
- Secure hidden key storage on removable drives.

---

## Installation

Either download the zip file in the latest releases, or use Pang Installer. 
> Note: Using the Pang Installer ensures PangCrypter is up-to-date.

---

## Usage

- Launch the app by double-clicking `PangCrypter.exe`.
- Open an encrypted `.enc` file using **File → Open**, or by assosciating `.enc` files with PangCrypter.exe and then double-clicking them.
- Edit your file securely in the built-in editor.
- When using USB key binding, make sure the corresponding USB drive is connected.

---

## Key Binding Modes

- **Key-only**: Encryption key stored and bound to a USB drive.
- **Password-only**: Use only a password to encrypt and decrypt.
- **Password + Key**: Requires both password and USB key to access the file.

---

## Security Notes

- Losing the USB drive or password means data is likely impossible to restore.
- Store your USB drives safely and keep your password strong but memorable.
- Keep in mind that you are responsible for safeguarding your data; Pang HQ is not liable for any data breaches or leaks.
- Keys are stored in a hidden `.pangcrypt_keys` folder on the USB drive.
- As keys are generated with the drive id of the selected USB drive, moving a key to a different drive is impossible. Do not do this, it will not work.

---

## Support

For issues or feature requests, please contact us [here](https://www.panghq.com/contact).

---

Enjoy secure and hassle-free encrypted editing with PangCrypter!
