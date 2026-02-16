"""Basic usage example for RansomwareShield.

This script demonstrates how to set up basic file system monitoring
with default detection settings.
"""

from ransomwareshield import RansomwareShield


def main():
    # Initialize the shield with default settings
    shield = RansomwareShield()

    # Add directories to monitor
    shield.monitor("/home/user/documents")
    shield.monitor("/home/user/pictures")

    # Start monitoring (runs until interrupted with Ctrl+C)
    print("Starting RansomwareShield monitoring...")
    print("Press Ctrl+C to stop.")
    try:
        shield.start()
    except KeyboardInterrupt:
        shield.stop()
        print("Monitoring stopped.")


if __name__ == "__main__":
    main()
