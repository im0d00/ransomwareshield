"""Command-line interface for RansomwareShield."""

import argparse
import sys

from ransomwareshield.shield import RansomwareShield


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ransomwareshield",
        description="Monitor directories for ransomware-like activity.",
    )
    parser.add_argument(
        "--watch",
        metavar="DIR",
        nargs="+",
        help="Directories to monitor.",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a YAML configuration file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose / debug logging.",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=None,
        help="Entropy threshold (0.0–8.0). Default: 7.5.",
    )
    parser.add_argument(
        "--max-changes",
        type=int,
        default=None,
        help="Max file changes per second before alerting. Default: 10.",
    )
    parser.add_argument(
        "--action",
        choices=["log", "alert", "kill_process"],
        default=None,
        help="Response action. Default: log.",
    )

    args = parser.parse_args(argv)

    if args.config:
        shield = RansomwareShield.from_config(args.config)
        # CLI flags can override config values
        if args.verbose:
            shield.verbose = True
            shield._setup_logging()
    elif args.watch:
        kwargs = {"verbose": args.verbose}
        if args.entropy_threshold is not None:
            kwargs["entropy_threshold"] = args.entropy_threshold
        if args.max_changes is not None:
            kwargs["max_changes_per_second"] = args.max_changes
        if args.action is not None:
            kwargs["action"] = args.action
        shield = RansomwareShield(**kwargs)
        for d in args.watch:
            shield.monitor(d)
    else:
        parser.print_help()
        sys.exit(1)

    print("Starting RansomwareShield …  Press Ctrl+C to stop.")
    try:
        shield.start()
    except KeyboardInterrupt:
        shield.stop()
        print("\nStopped.")
