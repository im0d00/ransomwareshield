"""Custom detection rules example for RansomwareShield.

This script shows how to define and register custom detection rules
to extend the default ransomware detection behavior.
"""

import os

from ransomwareshield import RansomwareShield


def detect_ransom_note(event):
    """Flag creation of common ransom note filenames."""
    ransom_note_names = [
        "README.txt",
        "DECRYPT_INSTRUCTIONS.txt",
        "HOW_TO_RECOVER.txt",
        "HELP_DECRYPT.html",
    ]
    if hasattr(event, "src_path"):
        filename = os.path.basename(event.src_path)
        if filename in ransom_note_names:
            return True
    return False


def detect_extension_change(event):
    """Flag files that have a suspicious new extension appended."""
    suspicious_extensions = [".locked", ".encrypted", ".crypt", ".enc"]
    if hasattr(event, "dest_path"):
        for ext in suspicious_extensions:
            if event.dest_path.endswith(ext):
                return True
    return False


def main():
    shield = RansomwareShield()

    # Register custom detection rules
    shield.add_rule("ransom_note_detection", detect_ransom_note)
    shield.add_rule("extension_change_detection", detect_extension_change)

    # Monitor a directory
    shield.monitor("/home/user/documents")

    print("Starting RansomwareShield with custom rules...")
    print("Press Ctrl+C to stop.")
    try:
        shield.start()
    except KeyboardInterrupt:
        shield.stop()
        print("Monitoring stopped.")


if __name__ == "__main__":
    main()
