"""
Example usage of pysnputils.

Install the package first:
    pip install -e .  (from the project root)
"""
import json
import os

from pysnputils.types import AttestationReport

DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(__file__), "reportV3.bin")


def main():
    input_path = input(f"Enter the path to the report file (default: {DEFAULT_REPORT_PATH}): ") or DEFAULT_REPORT_PATH
    with open(input_path, "rb") as f:
        report_v3 = f.read()
    parsed_report_v3 = AttestationReport.from_bytes(report_v3)
    print(json.dumps(parsed_report_v3.to_dict(), indent=4))
    proc_model = parsed_report_v3.get_processor_model()
    print(f"Processor model: {proc_model}")


if __name__ == "__main__":
    main()
