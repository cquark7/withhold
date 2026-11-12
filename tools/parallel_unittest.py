#!/usr/bin/env python3
"""Run independent unittest cases in a bounded number of processes."""

import argparse
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def run_shard(cases):
    return subprocess.run(
        [sys.executable, "-m", "unittest", "-q", *cases],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("modules", nargs="+")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(args.modules)
    if loader.errors:
        print("\n".join(loader.errors), file=sys.stderr)
        return 1
    cases = list(test_ids(suite))
    if not cases:
        print("No tests found", file=sys.stderr)
        return 1

    count = min(args.workers, len(cases))
    shards = [cases[index::count] for index in range(count)]
    failed = False
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(run_shard, shard) for shard in shards]
        for index, future in enumerate(futures, 1):
            result = future.result()
            print(f"Shard {index}/{count}:", flush=True)
            print(result.stdout, end="", flush=True)
            failed |= result.returncode != 0
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
