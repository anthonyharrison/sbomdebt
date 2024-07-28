# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.output import SBOMOutput

from sbomdebt.debt import SBOMdebt
from sbomdebt.version import VERSION

# CLI processing


def main(argv=None):
    argv = argv or sys.argv
    app_name = "sbomdebt"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOMDebt reports on the technical debt of a SBOM.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="name of SBOM file",
    )

    input_group.add_argument(
        "--updates",
        action="store",
        help="minimum number of updated versions to report (default: 2)",
        default=2,
    )

    input_group.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="verbose reporting",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "debug": False,
        "updates": 2,
        "verbose": False,
        "output_file": "",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] SBOM name must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Verbose", args["verbose"])
        print("Minimum number of updated versions", args["updates"])
        print("Output file", args["output_file"])

    debt_options = {
        "verbose": args["verbose"],
        "updates": int(args["updates"]),
        "debug": args["debug"],
    }
    try:
        sbom_debt = SBOMdebt(
            sbom=input_file, options=debt_options, output=args["output_file"]
        )

        sbom_debt.calculate()

        debt_data = sbom_debt.get_debt()
        if args["debug"]:
            print(debt_data)
        if args["output_file"] != "":
            debt_out = SBOMOutput(args["output_file"], "json")
            debt_out.generate_output(debt_data)
        else:
            for package in debt_data["packages"]:
                print(f"{package['name']}: {package['updates']} updates available")
            print(f"Package count: {debt_data['package_count']}")
            print(f"Debt count: {debt_data['debt_count']}")
            print(f"Debt ratio: {debt_data['ratio']}")

    except FileNotFoundError:
        print(f"[ERROR] {input_file} not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
