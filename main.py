import sys, psutil, os, platform, subprocess
from time import sleep
from webbrowser import open as webopen
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QLabel
from PyQt6.QtCore import QTimer, Qt, QEvent, QObject, pyqtSignal, QThread
from PyQt6.QtGui import QIcon
from main_ui import (
    EditorWidget, EncryptModeDialog, PasswordDialog, USBSelectDialog
)
from lib.encrypt import encrypt_file, decrypt_file, MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY
from lib.key import create_or_load_key, load_key_for_decrypt
from messagebox import PangMessageBox

from preferences import PreferencesDialog, PangPreferences
from styles import TEXT_COLOR, DARKER_BG, PURPLE, PURPLE_HOVER, BUTTON_TEXT


# List of known screen recording process names (case insensitive)
screen_recorders_lower = {
    "obs64.exe",      # OBS Studio 64-bit on Windows
    "obs32.exe",      # OBS Studio 32-bit on Windows
    "obs.exe",        # Generic OBS name
    "bandicam.exe",   # Bandicam
    "camtasia.exe",   # Camtasia
    "xsplit.exe",     # XSplit Broadcaster
    "ffmpeg.exe",     # ffmpeg (if used for recording)
    "screenrecorder.exe",
    "screencast-o-matic.exe",
    "sharex.exe",
    # Add other known recorders here if you want
}

def list_usb_drives():
    drives = []
    system = platform.system()

    if system == "Windows":
        # On Windows, use wmic to get removable drives
        try:
            output = subprocess.check_output('wmic logicaldisk where "drivetype=2" get deviceid', shell=True).decode()
            for line in output.strip().splitlines():
                line = line.strip()
                if line and line != "DeviceID":
                    drive_path = line + "\\"
                    if os.access(drive_path, os.W_OK):
                        drives.append(drive_path)
        except Exception:
            pass

    elif system == "Linux":
        # On Linux, check /media and /run/media for mounted removable drives
        media_paths = ["/media", "/run/media"]
        for media_root in media_paths:
            if os.path.exists(media_root):
                for user_folder in os.listdir(media_root):
                    user_path = os.path.join(media_root, user_folder)
                    if os.path.isdir(user_path):
                        for mount in os.listdir(user_path):
                            mount_path = os.path.join(user_path, mount)
                            if os.path.ismount(mount_path) and os.access(mount_path, os.W_OK):
                                drives.append(mount_path)

    elif system == "Darwin":
        # macOS: check /Volumes for mounted drives that are writable
        volumes_path = "/Volumes"
        if os.path.exists(volumes_path):
            for volume in os.listdir(volumes_path):
                vol_path = os.path.join(volumes_path, volume)
                if os.path.ismount(vol_path) and os.access(vol_path, os.W_OK):
                    drives.append(vol_path)
    else:
        PangMessageBox.warning(None, "Unsupported OS", "This script only supports Windows, Linux, and macOS.")

    return drives

class ScreenRecordingChecker(QObject):
    screen_recording_changed = pyqtSignal(bool)

    def __init__(self, check_interval=1):
        super().__init__()
        self.check_interval = check_interval
        self.running = True
        self._last_status = False
        self.cached_procs = set()

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            try:
                current_procs = set()
                # Gather current running process names, lowercase for matching
                for proc in psutil.process_iter(["name"]):
                    try:
                        pname = proc.info["name"]
                        if pname:
                            current_procs.add(pname.lower())
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                new_procs = current_procs - self.cached_procs
                self.cached_procs = current_procs

                # Only check new processes to reduce overhead
                recording_detected = False
                for pname in new_procs:
                    if pname in screen_recorders_lower:
                        recording_detected = True
                        break

                # Also if last status was True but process disappeared, update status
                if self._last_status and not recording_detected:
                    # Need to check if any screen recorder is still running
                    recording_detected = any(proc in screen_recorders_lower for proc in current_procs)

                if recording_detected != self._last_status:
                    self._last_status = recording_detected
                    self.screen_recording_changed.emit(recording_detected)

            except Exception as e:
                # Optionally log the error
                pass

            sleep(self.check_interval)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PangCrypter Editor")
        self.setWindowIcon(QIcon("logo.ico"))
        self.resize(800, 600)

        self.editor = EditorWidget()
        self.setCentralWidget(self.editor)
        self.editor.focusLost.connect(self.on_editor_focus_lost)

        self.saved_file_path = None
        self.current_mode = None
        self.cached_password = None
        self.cached_usb_key = None

        # Menus
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction("&Open", self.open_file).setShortcut("Ctrl+O")
        file_menu.addAction("&Save", self.on_save_triggered).setShortcut("Ctrl+S")
        file_menu.addAction("Save &As", self.save_file).setShortcut("Ctrl+Shift+S")
        file_menu.addAction("&Close", self.close_file).setShortcut("Ctrl+W")
        file_menu.addAction("&Preferences", self.open_preferences_dialog).setShortcut("Ctrl+,")

        edit_menu = self.menuBar().addMenu("&Edit")
        edit_menu.addAction("&Undo", self.editor.undo).setShortcut("Ctrl+Z")
        edit_menu.addAction("&Redo", self.editor.redo).setShortcut("Ctrl+Y")
        edit_menu.addSeparator()
        edit_menu.addAction("Cu&t", self.editor.cut).setShortcut("Ctrl+X")
        edit_menu.addAction("&Copy", self.editor.copy).setShortcut("Ctrl+C")
        edit_menu.addAction("&Paste", self.editor.paste).setShortcut("Ctrl+V")
        edit_menu.addSeparator()
        edit_menu.addAction("Select &All", self.editor.selectAll).setShortcut("Ctrl+A")
        edit_menu.addSeparator()
        edit_menu.addAction("Reset Formatting", self.editor.reset_formatting).setShortcut("Ctrl+Space")
        edit_menu.addAction("Increase Font Size", lambda: self.editor.change_font_size(1)).setShortcut("Ctrl+Shift+>")
        edit_menu.addAction("Decrease Font Size", lambda: self.editor.change_font_size(-1)).setShortcut("Ctrl+Shift+<")

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("&Help", self.open_help_page).setShortcut("F1")

        # Style
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: #121212; color: #eee; }}
            QTextEdit {{ background-color: #1e1e1e; color: #ddd; font-family: Consolas, monospace; font-size: 14px; }}
            QMenuBar {{ background-color: #222; color: #eee; }}
            QMenu {{ background-color: #222; color: #eee; }}
            QMenu::item:selected {{ background-color: #444; }}
            QPushButton {{ background-color: #333; color: #eee; border-radius: 5px; padding: 5px; }}
            QPushButton:hover {{ background-color: #555; }}
            QLineEdit, QComboBox {{ background-color: #222; color: #eee; border: 1px solid #555; border-radius: 3px; padding: 3px; }}
        """)

        # Hidden label when editor is hidden
        self.hidden_label = QLabel(
            "Editor hidden due to focus loss. Click here to restore.", self
        )
        self.hidden_label.setStyleSheet(f"""
            color: {TEXT_COLOR};
            background-color: {DARKER_BG};
            font-size: 13px;
            padding: 12px 14px;
            border: 1.5px solid {PURPLE};
            border-radius: 6px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        """)
        self.hidden_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hidden_label.hide()
        self.hidden_label.setGeometry(50, 50, 700, 100)
        self.hidden_label.mousePressEvent = self.on_hidden_label_clicked

        # Autosave timer
        self.autosave_timer = QTimer(singleShot=True)
        self.autosave_timer.setInterval(1000)
        self.autosave_timer.timeout.connect(self.autosave)
        self.editor.textChanged.connect(lambda: self.autosave_timer.start())

        # Focus cooldown timer for screen recording hide
        self.cooldown_timer = QTimer()
        self.cooldown_timer.setInterval(1000)
        self.cooldown_timer.timeout.connect(self.update_cooldown)
        self.cooldown_remaining = 0
        self.allow_editor_activation = True

        # Tab setting from preferences
        self.editor.tab_setting = PangPreferences.tab_setting

        # Screen recording checker in thread
        self.screen_recorder_thread = QThread()
        self.screen_recorder_checker = ScreenRecordingChecker()
        self.screen_recorder_checker.moveToThread(self.screen_recorder_thread)
        self.screen_recorder_thread.started.connect(self.screen_recorder_checker.run)
        self.screen_recorder_checker.screen_recording_changed.connect(self.on_screen_recording_changed)
        self.screen_recorder_thread.start()

        # Track window focus
        self.installEventFilter(self)
    
    def open_help_page(self):
        webopen("https://www.panghq.com/tools/pangcrypter/help")
    
    def on_save_triggered(self):
        if self.saved_file_path is None:
            # No file open: prompt Save As
            self.save_file()
        else:
            # File is open: autosave instead
            self.autosave()

    def open_preferences_dialog(self):
        dlg = PreferencesDialog(self)
        if dlg.exec():
            # Preferences were saved by dlg.accept()
            # Just update the editor with the new setting
            self.editor.set_tab_setting(PangPreferences.tab_setting)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.WindowActivate:
            if PangPreferences.screen_recording_hide_enabled and not self.allow_editor_activation:
                self.cooldown_remaining = PangPreferences.recording_cooldown
                self.update_hidden_label_for_cooldown()
                self.cooldown_timer.start()
            return False
        elif event.type() == QEvent.Type.WindowDeactivate:
            if PangPreferences.screen_recording_hide_enabled:
                self.cooldown_timer.stop()
            return False
        return super().eventFilter(obj, event)
    
    def update_cooldown(self):
        self.cooldown_remaining -= 1
        if self.cooldown_remaining <= 0:
            self.allow_editor_activation = True
            self.cooldown_timer.stop()
            self.try_restore_editor()
        else:
            self.update_hidden_label_for_cooldown()
    
    def update_hidden_label_for_cooldown(self):
        self.hidden_label.setText(
            f"Screen recording program detected.\n"
            f"Make sure to close this window before recording.\n"
            f"Keep this window focused for {self.cooldown_remaining} seconds to restore editor."
        )
    
    def on_screen_recording_changed(self, is_recording):
        self.allow_editor_activation = not is_recording
        if is_recording:
            self.hide_editor_and_show_label()
        elif self.hidden_label.isVisible():
            self.try_restore_editor()
    
    def on_editor_focus_lost(self):
        if not PangPreferences.tab_out_hide_enabled:
            return
        
        active_window = QApplication.activeWindow()

        if active_window is None or not (active_window == self or self.isAncestorOf(active_window)):
            self.hide_editor_and_show_label()
    
    def hide_editor_and_show_label(self):
        self.editor.hide()
        self.hidden_label.setText("Editor hidden due to focus loss. Click here to restore.")
        self.hidden_label.show()
    
    def try_restore_editor(self):
        if not self.allow_editor_activation:
            return False
        
        self.hidden_label.hide()
        self.editor.show()
        self.editor.setFocus()
        return True

    def on_hidden_label_clicked(self, event):
        self.try_restore_editor()

    def check_focus_time(self):
        if self.focus_timer.isValid():
            elapsed_sec = self.focus_timer.elapsed() / 1000
            if elapsed_sec >= PangPreferences.recording_cooldown:
                self.allow_editor_activation = True
                self.try_restore_editor()

    def on_text_changed(self):
        self.autosave_timer.start()  # reset timer on each key press

    def autosave(self):
        # To avoid lag, autosave only if we have keys cached:
        if self.cached_password is None and self.cached_usb_key is None:
            return
        
        # Only autosave if file is already saved
        if not self.saved_file_path:
            return
        
        try:
            # Encrypt current editor content
            encrypt_file(
                self.editor.toHtml().encode("utf-8"),
                self.saved_file_path,
                self.current_mode,
                password=self.cached_password,
                usb_key=self.cached_usb_key,
            )
            print(f"Autosaved encrypted file to {self.saved_file_path}")
        except Exception as e:
            PangMessageBox.warning(self, "Autosave failed", f"Could not autosave encrypted file:\n{e}")

    def check_usb_present(self):
        usbs = list_usb_drives()
        if not usbs:
            PangMessageBox.warning(self, "No USB", "No USB drives detected. Please plug in your Pang USB key.")
            return None
        return usbs

    def save_file(self):
        usbs = self.check_usb_present()

        dlg = EncryptModeDialog(self)
        if not dlg.exec_():
            return

        mode = dlg.mode

        password = None
        if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
            pwd_dlg = PasswordDialog(self, warning=(mode == MODE_KEY_ONLY))
            if not pwd_dlg.exec_():
                return
            password = pwd_dlg.password

        random_key = None  # this is the actual key used to encrypt

        if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
            if not usbs:
                return

            usb_dlg = USBSelectDialog(usbs, self)
            if not usb_dlg.exec_():
                return

            selected_usb_path = usb_dlg.selected_usb

        path, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", filter="Encrypted Files (*.enc)")
        if not path:
            return

        if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
            combined_key, random_key = create_or_load_key(selected_usb_path, os.path.basename(path))
            # combined_key saved on disk already by create_or_load_key

            if not random_key:
                random_key = load_key_for_decrypt(selected_usb_path, os.path.basename(path))

        try:
            encrypt_file(
                self.editor.toHtml().encode("utf-8"),
                path,
                mode,
                password=password,
                usb_key=random_key,  # pass the in-memory key to encrypt_file
            )
        except Exception as e:
            PangMessageBox.critical(self, "Save failed", f"Failed to save encrypted file:\n{e}")
            return

        self.saved_file_path = path
        self.update_window_title(self.saved_file_path)
        self.current_mode = mode
        self.cached_password = password
        self.cached_usb_key = random_key  # cache random_key (in-memory key) for reuse

        PangMessageBox.information(self, "Saved", "File saved successfully.")

    def open_file(self, path: str | None = None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Open encrypted file", filter="Encrypted Files (*.enc)")
            if not path:
                return

        try:
            with open(path, "rb") as f:
                mode_byte = f.read(1)
                if not mode_byte:
                    PangMessageBox.critical(self, "Error", "File is empty or invalid")
                    return
                mode = mode_byte[0]
                if mode not in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                    PangMessageBox.critical(self, "Error", f"Unknown encryption mode: {mode}")
                    return
        except Exception as e:
            PangMessageBox.critical(self, "Error", f"Failed to read file: {e}")
            return

        password = None
        random_key = None

        if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
            pwd_dlg = PasswordDialog(self, warning=(mode == MODE_KEY_ONLY))
            if not pwd_dlg.exec_():
                return
            password = pwd_dlg.password

        if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
            usbs = self.check_usb_present()
            if not usbs:
                return
            usb_dlg = USBSelectDialog(usbs, self)
            if not usb_dlg.exec_():
                return

            selected_usb_path = usb_dlg.selected_usb

            try:
                random_key = load_key_for_decrypt(selected_usb_path, os.path.basename(path))
            except Exception as e:
                PangMessageBox.critical(self, "Error", f"Failed to load USB key:\n{e}")
                return

        try:
            plaintext = decrypt_file(path, password=password, usb_key=random_key)
        except Exception as e:
            PangMessageBox.critical(self, "Error", f"Failed to decrypt file:\n{e}")
            return

        self.editor.setHtml(plaintext.decode("utf-8"))
        self.saved_file_path = path
        self.update_window_title(self.saved_file_path)
        self.current_mode = mode
        self.cached_password = password
        self.cached_usb_key = random_key  # cache in-memory random_key

        PangMessageBox.information(self, "Opened", "File opened successfully.")
    
    def close_file(self):
        content_empty = self.editor.toPlainText().strip() == ""
        if self.saved_file_path is None and content_empty:
            # Nothing to close or clear
            return

        if not content_empty:
            ret = PangMessageBox.question(
                self,
                "Close File",
                "Are you sure you want to close the current file? Unsaved changes will be lost.",
                buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                default=PangMessageBox.StandardButton.No
            )

            if ret == PangMessageBox.StandardButton.No:
                return

        # Clear state and editor
        self.saved_file_path = None
        self.update_window_title(self.saved_file_path)
        self.current_mode = None
        self.cached_password = None
        self.cached_usb_key = None
        self.editor.clear()
    
    def update_window_title(self, filename: str | None):
        base_title = "PangCrypter"
        if filename:
            # Remove .enc extension if present
            name_without_ext = os.path.splitext(os.path.basename(filename))[0]
            self.setWindowTitle(f"Editing {name_without_ext} - {base_title}")
        else:
            self.setWindowTitle(base_title)

def main():
    app = QApplication(sys.argv)
    win = MainWindow()

    # If there's an argument, try opening it
    if len(sys.argv) > 1:
        file_arg = sys.argv[1]
        if os.path.isfile(file_arg) and file_arg.lower().endswith(".enc"):
            try:
                win.open_file(file_arg)
            except Exception as e:
                print(f"Failed to open {file_arg}: {e}")

    win.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()