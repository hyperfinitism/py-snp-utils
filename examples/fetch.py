"""
Example usage of pysnputils.fetch.
"""
import os
from cryptography.hazmat.primitives.serialization import Encoding
from pysnputils.types import AttestationReport
from pysnputils.fetch import fetch_vcek, fetch_ca, fetch_crl

DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(__file__), "reportV3.bin")
DEFAULT_OUTPUT_DIR = os.path.dirname(__file__)

def main():
    input_path = input(f"Enter the path to the report file (default: {DEFAULT_REPORT_PATH}): ") or DEFAULT_REPORT_PATH
    proc_model = input("Enter the processor model (default: autodetect): ") or None
    output_dir = input(f"Enter the path to the output directory (default: {DEFAULT_OUTPUT_DIR}): ") or DEFAULT_OUTPUT_DIR
    with open(input_path, "rb") as f:
        report_bin = f.read()
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=proc_model)
    vcek = fetch_vcek(parsed_report)
    with open(os.path.join(output_dir, "vcek.pem"), "wb") as f:
        f.write(vcek.public_bytes(encoding=Encoding.PEM))
    ca = fetch_ca(parsed_report)
    with open(os.path.join(output_dir, "ask.pem"), "wb") as f:
        f.write(ca[0].public_bytes(encoding=Encoding.PEM))
    with open(os.path.join(output_dir, "ark.pem"), "wb") as f:
        f.write(ca[1].public_bytes(encoding=Encoding.PEM))
    crl = fetch_crl(parsed_report)
    with open(os.path.join(output_dir, "crl.pem"), "wb") as f:
        f.write(crl.public_bytes(encoding=Encoding.PEM))

if __name__ == "__main__":
    main()
