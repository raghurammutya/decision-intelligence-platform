#!/usr/bin/env bash
set -euo pipefail

python3 -m dip_framework validate
python3 -m dip_framework trust-loop --out reports/trust-loop
python3 -m dip_framework release-pack --version v2.1.0-pre
python3 -m unittest discover -s tests -p 'test_*.py'
