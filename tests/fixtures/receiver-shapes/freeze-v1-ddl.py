#!/usr/bin/env python3
"""Extract immutable receiver DDL evidence from an exact producer revision.

No application database is opened. Rust evaluates the producer's DDL constants
in a disposable directory; the expected release digest must match before output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "show", f"{args.revision}:src/schema/ddl.rs"])
    with tempfile.TemporaryDirectory(prefix="receiver-frozen-ddl-") as temporary:
        root = Path(temporary)
        (root / "ddl.rs").write_bytes(source)
        (root / "main.rs").write_text('mod ddl; fn main() { for statement in ddl::DDL_STATEMENTS { print!("{}\\0", statement); } }\n')
        subprocess.run(["rustc", "--edition=2021", "-Adead_code", str(root / "main.rs"), "-o", str(root / "extract")], check=True)
        raw = subprocess.check_output([str(root / "extract")])
    statements = raw.decode().split("\0")
    assert statements.pop() == ""
    actual = hashlib.sha256("\n;\n".join(statements).encode()).hexdigest()
    assert actual == args.sha256, (actual, args.sha256)
    args.output.write_text(json.dumps(statements, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"revision": args.revision, "statements": len(statements), "sha256": actual}))


if __name__ == "__main__":
    main()
