# build.py (inside pangcrypt/)
import os
import shutil
import PyInstaller.__main__

# Clean old build/dist
for folder in ("build", "dist"):
    if os.path.exists(folder):
        shutil.rmtree(folder)

# Main script inside same folder
entry_file = "main.py"

# PyInstaller build
PyInstaller.__main__.run([
    entry_file,
    "--name", "PangCrypter",
    "--onefile",
    "--windowed",
    "--noconfirm",
    "--icon", "logo.ico",
    "--add-data", "dropdown.svg;.",
    "--add-data", "dropup.svg;.",
    "--add-data", "preferences.json;.",
    "--add-data", "lib;lib",  # lib folder included as subfolder
    "--version-file", "version.txt",
])

print("\n✅ Build complete! Check the 'dist' folder for PangCrypter.exe")
