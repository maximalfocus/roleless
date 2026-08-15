#!/bin/sh
set -eu
pytest
ruff check .
ruff format --check .
mypy
