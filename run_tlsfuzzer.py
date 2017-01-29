#!/usr/bin/env python3
import os
from os import path

tlsfuzzer_path = "../tlsfuzzer/"

scripts = os.listdir(path.join(tlsfuzzer_path, "scripts"))

os.system("mkdir -p {path}/out".format(path=tlsfuzzer_path))

def includes(lines, s):
    return any(s in l for l in lines)

def classify(lines):
    successful = -1
    failed = -1
    errors = set()
    info = ""

    for l in lines:
        l = l.strip()
        if l.startswith("successful"):
            successful = int(l.split(" ")[1])
        if l.startswith("failed"):
            failed = int(l.split(" ")[1])
        if (l.startswith("socket.timeout") or
                l.startswith("AssertionError:") or
                l.startswith("NotImplementedError") or
                l.startswith("assert ")):
            errors.add(l)

    errors = sorted(errors)

    return successful, failed, errors, info

requires_private_key = [
        "test-certificate-verify.py",
        "test-certificate-malformed.py",
        "test-certificate-verify-malformed.py",
        "test-rsa-sigs-on-certificate-verify.py",
        "test-certificate-verify-malformed-sig.py",
    ]

successful_scripts = 0
failed_scripts = 0

for i, script in enumerate(scripts):
    print("{:2}/{}> {:80}".format(i, len(scripts), script), end="")

    args = ""
    if script in requires_private_key:
        args += "-k /tmp/https_key.pem -c /tmp/https_cert.pem"

    os.system(
        "cd {path}; PYTHONPATH=. python scripts/{script} {args} &> out/{script}.log".
        format(path=tlsfuzzer_path, args=args, script=script))

    out_lines = list(open(path.join(tlsfuzzer_path, "out", script + ".log")).readlines())
    successful, failed, errors, info = classify(out_lines)
    print("| success:{:4} fail:{:4} {:7} {}".format(successful, failed, len(out_lines), info))
    for error in errors:
        print("    - {}".format(error))

    if failed:
        failed_scripts += 1
    else:
        successful_scripts += 1

print("{} successful scripts, {} failed scripts".format(successful_scripts, failed_scripts))
