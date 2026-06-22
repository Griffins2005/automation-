# Cryptographic Validation Automation

This repository contains a terminal-first Python MVP for validating cryptographic
algorithm outputs against NIST-style test vectors.

The first implemented flow supports AES Known Answer Tests from `.rsp` files
using a Python DUT backed by PyCryptodome.

## Quick Start

Install the package with development dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Run the sample AES-CBC encryption validation:

```bash
python3 -m crypto_validation \
  --algorithm AES \
  --mode CBC \
  --operation encrypt \
  --test-type KAT \
  --vector-file sample_vectors/aes/aes_cbc_128.rsp \
  --dut python \
  --report-format json \
  --report-dir reports
```

Expected summary:

```text
Total Tests: 2
Passed: 2
Validation Failures: 0
```

## Detailed Proposal

See [`CRYPTO_VALIDATION_FRAMEWORK.md`](CRYPTO_VALIDATION_FRAMEWORK.md) for the
full technical proposal, architecture, roadmap, data contracts, and design
considerations.
