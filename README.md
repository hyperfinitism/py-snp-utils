# py-snp-utils

**py-snp-utils** (`pysnputils`) is a Python library for parsing SNP reports, fetching VCEK certificate chains, and verifying them.

## Installation

### Requirements

- Python 3.12+ (Tested with Python 3.12.7)

### Install from repository

```bash
git clone https://github.com/acompany-develop/py-snp-utils
cd py-snp-utils
pip install -e .
```

## Usage

The Python module `pysnputils` consists of the following submodules:
| Submodules | Descriptions |
| :- | :- |
| `types` | attestation report types and parsers |
| `fetch` | (to be implemented) functions to fetch VCEK certificate chains from AMD KDS |
| `verify` | (to be implemented) functions to verify VCEK certificate chains and SNP reports |

### Example code

```python
from pysnputils.types import AttestationReport

with open("report.bin", "rb") as f:
    report_bin = f.read()

report_parsed = AttestationReport.from_bytes(report_bin)
report_dict = report_parsed.to_dict()
```

### CLI Tools / Example Scripts

The `examples/` directory contains scripts that serve as both usage examples and command-line tools. Sample inputs are also included.

| Script | Description |
|--------|-------------|
| `display.py` | Display SNP attestation report in JSON format |

```bash
# Display SNP report in JSON format
python examples/display.py
# Default input: ./examples/reportV3.bin
```
