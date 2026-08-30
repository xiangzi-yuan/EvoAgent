"""Prepare immutable Git worktrees for the reviewed-PR benchmark manifest."""
import argparse
import json
import os
import subprocess
from typing import List, Optional


def _run(arguments: List[str], cwd: Optional[str] = None) -> str:
    result = subprocess.run(
        arguments, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=900, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "%s failed: %s" % (" ".join(arguments), result.stderr.strip()[:2000])
        )
    return result.stdout.strip()


def _safe_child(root: str, name: str) -> str:
    child = os.path.abspath(os.path.join(root, name))
    boundary = os.path.abspath(root) + os.sep
    if not child.startswith(boundary):
        raise ValueError("path must remain below its configured root")
    return child


def prepare(item: dict, cache_root: str, checkout_root: str) -> str:
    repository = str(item["repository"])
    pull_request = int(item["pull_request"])
    snapshot = str(item["snapshot_sha"]).lower()
    base = str(item["base_sha"]).lower()
    cache = _safe_child(cache_root, repository.replace("/", "__"))
    checkout = _safe_child(checkout_root, str(item["checkout"]))
    if not os.path.isdir(cache):
        print("clone %s" % repository, flush=True)
        _run([
            "git", "clone", "--filter=blob:none", "--no-checkout",
            "https://github.com/%s.git" % repository, cache,
        ])
    for revision in (base, snapshot):
        exists = subprocess.run(
            ["git", "cat-file", "-e", revision + "^{commit}"], cwd=cache,
            capture_output=True, check=False,
        ).returncode == 0
        if not exists:
            print("fetch %s PR#%d %s" % (repository, pull_request, revision[:12]), flush=True)
            _run(["git", "fetch", "--no-tags", "origin", revision], cwd=cache)
    if os.path.isdir(checkout):
        actual = _run(["git", "rev-parse", "HEAD"], cwd=checkout).lower()
        if actual != snapshot:
            raise ValueError(
                "existing checkout %s is at %s, expected %s"
                % (checkout, actual, snapshot)
            )
    else:
        print("checkout %s PR#%d at %s" % (repository, pull_request, snapshot[:12]), flush=True)
        _run(["git", "worktree", "add", "--detach", checkout, snapshot], cwd=cache)
    return checkout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--checkout-root", required=True)
    args = parser.parse_args()
    cache_root = os.path.abspath(args.cache_root)
    checkout_root = os.path.abspath(args.checkout_root)
    os.makedirs(cache_root, exist_ok=True)
    os.makedirs(checkout_root, exist_ok=True)
    count = 0
    with open(args.manifest, "r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                prepare(json.loads(raw), cache_root, checkout_root)
            except Exception as exc:
                raise RuntimeError("manifest line %d: %s" % (line_number, exc)) from exc
            count += 1
    print("prepared %d immutable review snapshots" % count)


if __name__ == "__main__":
    main()
