#!/usr/bin/env python3
"""QraftFlow F01-F07 read-only candidate snapshot preflight; no source output.

The fixed policy is non-secret Git object metadata, not source code. This process
is invoked only in the credential-scoped restore step. Never run candidate code
from this process or print REST response/error bodies.
"""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import sys
import urllib.request

REPO = "yxlnetcom/QraftFlow-Creator-OS"
BATCH = "F01-F07-20260928"
BASE = "fb27377988179da6076fef5107dcba87d1f1980d"
SHA = re.compile(r"[0-9a-f]{40}\Z")
# Exact approved scope. None means an approved new file; all modes are 100644.
POLICY = {
    "Sources/QraftFlowPersistence/SHA256.swift": ("c40003b43b7a76cf7b1c6d5e00b6472c8f69ad77", "60ac87e2af74f33c9fd7dbc0163d11718fa4e958"),
    "Sources/QraftFlowPersistence/UploadBatchService.swift": ("6719297e6b7c830fad89da4a71822d5ce91832a8", "638f0bd9525524c0cb0ab139831a5c168573fe2a"),
    "Sources/QraftFlowPersistence/M6MediaService.swift": ("4dcb2e0d53e884c616f009974772b83955b66d74", "164b5551cd43a0a09a7055660d13e2371a850af2"),
    "Sources/QraftFlowLocalServer/main.swift": ("cfb6946f20547458ae47b4621ae9174e40f8b4c3", "dedef497f39aba7ff5342b9954efd36d2ffaa87f"),
    "Sources/QraftFlowLocalServer/Web/app.js": ("9109c05c2b3f23c731cdd97a21894d87003a2f0f", "3da5dbae979305095db007f42009a7ad45ec06b7"),
    "Sources/QraftFlowLocalServer/Web/style.css": ("1ab6e9637a97fc7101a34df0528a79e985217dab", "f6cd4e11b20b4a847ac58afda4d874d9a09a3bb7"),
    "Sources/QraftFlowPersistence/M2BusinessService.swift": ("d94afea2c6efe317e84d44fb3c1547c12c92f529", "0aa12641d07879a1dea4b5b122671f1be0d2c843"),
    "Sources/QraftFlowPersistence/V1BusinessClosureService.swift": ("06a536207e59fb52c6955f5dafc35d2814ab19bb", "81a8e1e62906d8703392ce44854c4741536a65f4"),
    "Sources/QraftFlowPersistence/RequiredTopicParser.swift": ("b9bed76e9cc5a379357d5a6f97b67619b2559bc2", "d6433c3eec3eaa538058dae684562adfea413008"),
    "Sources/QraftFlowPersistence/BriefDocumentParser.swift": ("2d60d43f9aa8dc2734a6e6acb3cfbf327bfbf42f", "9949d506555164a4cab8f2845ae9b26aca616a94"),
    "Tests/QraftFlowCoreTests/GateARepairRegressionTests.swift": (None, "e4d65fae327719a80c91e9e0485a820c2e04cc68"),
    "Tests/QraftFlowCoreTests/V1BusinessClosureTests.swift": ("90adb81f5387d6fe13c705f114fee6eb67d3971f", "87f69a485e28798dc577973e323e5990c7a0dec0"),
    "Tests/QraftFlowCoreTests/M2BusinessMVPTests.swift": ("8eec7b26aff98f1ff4d71254680e3110533c962f", "70b2843cbb55e8b58768033c7408db716dff61ff"),
}

def check_path(path):
    if (not isinstance(path, str) or not path or path.startswith(("/", "-"))
            or "\\" in path or "\x00" in path or any(ord(c) < 32 for c in path)):
        raise ValueError("unsafe path")
    parts = path.split("/")
    if any(p in ("", ".", "..", ".git") for p in parts):
        raise ValueError("unsafe path components")
    return path

def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def run(*args, cwd):
    return subprocess.check_output(args, cwd=cwd, stderr=subprocess.DEVNULL).decode().strip()

def api(path, token):
    url = "https://api.github.com/repos/" + REPO + "/git/" + path
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "qraftflow-preflight",
    })
    with urllib.request.urlopen(req, timeout=45) as response:
        return json.load(response)

def get_entries(tree):
    if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise ValueError("tree truncated or malformed")
    entries = {}
    for e in tree["tree"]:
        p = check_path(e["path"])
        if p in entries or e.get("type") not in ("blob", "tree"):
            raise ValueError("duplicate/unapproved entry type")
        mode = e.get("mode")
        if (e["type"] == "tree" and mode != "040000") or (e["type"] == "blob" and mode not in ("100644", "100755")):
            raise ValueError("symlink/submodule/unapproved file mode")
        if not SHA.fullmatch(e.get("sha", "")):
            raise ValueError("invalid blob/tree SHA")
        entries[p] = (e["type"], mode, e["sha"])
    return entries

def check_scope(before, after):
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    if changed != set(POLICY) or len(changed) != 13:
        raise ValueError("candidate scope mismatch")
    for p, (old, new) in POLICY.items():
        if before.get(p) != (("blob", "100644", old) if old else None):
            raise ValueError("unexpected baseline entry")
        if after.get(p) != ("blob", "100644", new):
            raise ValueError("unexpected target entry")
    if sum(old is None for old, _ in POLICY.values()) != 1:
        raise ValueError("bad policy")

def verify_on_disk(root, entries):
    actual = set(run("git", "ls-files", "--cached", "--full-name", cwd=root).splitlines())
    expected = {p for p, (kind, _, _) in entries.items() if kind == "blob"}
    if actual != expected:
        raise ValueError("checkout file set mismatch")
    for path in sorted(expected):
        _, mode, sha = entries[path]
        full = root / path
        if not full.is_file() or full.is_symlink():
            raise ValueError("missing or symbolic file")
        bits = stat.S_IMODE(full.stat().st_mode)
        if bool(bits & 0o111) != (mode == "100755"):
            raise ValueError("file mode mismatch")
        if blob_sha(full.read_bytes()) != sha:
            raise ValueError("file contents mismatch")

def restore(args):
    if args.batch_id != BATCH or args.base_sha != BASE or not SHA.fullmatch(args.candidate_tree_sha):
        raise ValueError("unapproved batch / baseline / SHA")
    token = os.environ.get("QF_PREFLIGHT_READ_TOKEN", "")
    if not token:
        raise ValueError("read token not provided")
    root = Path(args.workspace).resolve(strict=True)
    if not (root / ".git").is_dir() or run("git", "rev-parse", "HEAD", cwd=root) != BASE:
        raise ValueError("workspace is not exact baseline")
    commit = api("commits/" + BASE, token)
    base_tree_sha = commit["tree"]["sha"]
    if run("git", "rev-parse", "HEAD^{tree}", cwd=root) != base_tree_sha:
        raise ValueError("baseline tree mismatch")
    original = api("trees/" + base_tree_sha + "?recursive=1", token)
    candidate = api("trees/" + args.candidate_tree_sha + "?recursive=1", token)
    if original.get("sha") != base_tree_sha or candidate.get("sha") != args.candidate_tree_sha:
        raise ValueError("API returned different tree")
    before, after = get_entries(original), get_entries(candidate)
    check_scope(before, after)
    verify_on_disk(root, before)
    # Read all candidate payloads from private Git Blobs API; never print bytes.
    for path, (_, target) in sorted(POLICY.items()):
        obj = api("blobs/" + target, token)
        if obj.get("sha") != target or obj.get("encoding") != "base64":
            raise ValueError("blob response mismatch")
        data = base64.b64decode(obj["content"], validate=False)
        if blob_sha(data) != target or len(data) != obj.get("size"):
            raise ValueError("blob byte integrity mismatch")
        dest = root / path
        if not dest.parent.is_dir() or dest.parent.is_symlink() or dest.is_symlink():
            raise ValueError("unsafe destination")
        for ancestor in dest.parents:
            if ancestor == root:
                break
            if ancestor.is_symlink():
                raise ValueError("symlink ancestor")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(dest, flags, 0o644)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.chmod(dest, 0o644)
    run("git", "add", "--", ".", cwd=root)
    if run("git", "write-tree", cwd=root) != args.candidate_tree_sha:
        raise ValueError("local candidate Tree SHA mismatch")
    verify_on_disk(root, after)
    print("P0_RESTORE PASS: exact baseline; 13 approved changes; full candidate tree and blobs verified")

def audit(workspace):
    if any(os.environ.get(k) for k in ("QF_PREFLIGHT_READ_TOKEN", "QRAFTFLOW_SOURCE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GIT_ASKPASS")):
        raise ValueError("credential environment exists in test process")
    root = Path(workspace).resolve(strict=True)
    configs = [root / ".git" / "config", Path.home() / ".gitconfig", Path.home() / ".git-credentials", Path.home() / ".netrc"]
    for config in configs:
        if config.exists() and config.is_file():
            raw = config.read_text(errors="replace").lower()
            if any(term in raw for term in ("extraheader", "authorization:", "github_pat_", "ghp_", "password=", "credential.helper=store")):
                raise ValueError("persisted credential configuration")
    print("P1_CREDENTIAL_AUDIT PASS: known token environment/configuration surfaces absent")

def tests(workspace, platform):
    """Only trusted fixed commands; all candidate process output stays off public logs."""
    root = Path(workspace).resolve(strict=True)
    if platform not in ("linux", "macos"):
        raise ValueError("invalid platform")
    audit(workspace)
    checks = [
        ("web-app-syntax", ["node", "--check", "Sources/QraftFlowLocalServer/Web/app.js"]),
        ("web-service-worker-syntax", ["node", "--check", "Sources/QraftFlowLocalServer/Web/sw.js"]),
        ("repository-security", ["bash", "./scripts/check.sh"]),
        ("release-manifest-regression", ["bash", "./scripts/test_release_manifest.sh"]),
        ("swift-build", ["swift", "build"]),
        ("swift-test-all", ["swift", "test"]),
        ("swift-F01-http-framing", ["swift", "test", "--filter", "M2HTTPFramingTests"]),
        ("swift-F01-media", ["swift", "test", "--filter", "M6MediaPipelineTests"]),
        ("swift-F01-upload", ["swift", "test", "--filter", "UploadBatchTests"]),
        ("swift-F05-brief", ["swift", "test", "--filter", "V1BusinessClosureTests"]),
        ("swift-F05-topics", ["swift", "test", "--filter", "GateARepairRegressionTests"]),
        ("swift-F05-human-state", ["swift", "test", "--filter", "M2BusinessMVPTests"]),
        ("process-http-golden", ["bash", "./scripts/test_v1_http_golden.sh"]),
    ]
    if platform == "macos":
        checks += [("macos-release-shell-syntax", ["bash", "-n", "scripts/build_app.sh", "scripts/package_dmg.sh", "scripts/release_manifest.sh", "scripts/notarize.sh"])]
    failed = False
    for label, command in checks:
        # Untrusted scripts and compiler diagnostics are never streamed or uploaded.
        with open(os.devnull, "wb") as sink:
            result = subprocess.run(command, cwd=root, stdout=sink, stderr=sink,
                                    env={k: v for k, v in os.environ.items()
                                         if k not in ("QF_PREFLIGHT_READ_TOKEN", "QRAFTFLOW_SOURCE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GIT_ASKPASS")},
                                    timeout=1800, check=False)
        print(f"{platform}:{label}:exit={result.returncode}")
        failed |= result.returncode != 0
    # Mandatory targeted F01 range/stream regression is not present in current
    # candidate tests. Fail closed rather than calling generic HTTP smoke a PASS.
    result = subprocess.run(["swift", "test", "list"], cwd=root, capture_output=True,
                            timeout=180, check=False)
    names = result.stdout.decode("utf-8", "replace") if result.returncode == 0 else ""
    required = ("GateARepairRegressionTests", "V1BusinessClosureTests", "M2HTTPFramingTests")
    discovered = all(name in names for name in required)
    print(f"{platform}:test-discovery:{'PASS' if discovered else 'FAIL'}")
    failed |= not discovered
    # A dedicated process-level test must exercise authenticated byte ranges,
    # 416, motion/original streaming outside lock. No existing test identified.
    range_coverage = any(("test" in line.lower() and "range" in line.lower() and "stream" in line.lower())
                         for line in names.splitlines())
    print(f"{platform}:F01-range-stream-coverage:{'PASS' if range_coverage else 'BLOCKED'}")
    failed |= not range_coverage
    if failed:
        raise ValueError("P1 failed or required regression coverage missing")
    print(f"P1_{platform.upper()} PASS")

def selftest():
    for p in ("../x", "/tmp/a", "a//b", "a/./b", "a/.git/config", "a\\b"):
        try: check_path(p)
        except ValueError: pass
        else: raise ValueError("unsafe path accepted")
    before = {p: ("blob", "100644", old) for p, (old, _) in POLICY.items() if old}
    after = dict(before)
    for p, (_, target) in POLICY.items(): after[p] = ("blob", "100644", target)
    check_scope(before, after)
    for invalid in (dict(after, extra=("blob", "100644", "a" * 40)), dict(after, **{next(iter(POLICY)): ("blob", "120000", "a" * 40)})):
        try: check_scope(before, invalid)
        except ValueError: pass
        else: raise ValueError("unapproved candidate accepted")
    assert blob_sha(b"test") == "30d74d258442c7c65512eafab474568dd706c430"
    print("SELFTEST PASS: scope, paths, modes and Git blob hashing")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("restore", "audit", "selftest", "test"))
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--candidate-tree-sha", default="")
    parser.add_argument("--batch-id", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--platform", default="")
    args = parser.parse_args()
    try:
        if args.action == "restore": restore(args)
        elif args.action == "audit": audit(args.workspace)
        elif args.action == "test": tests(args.workspace, args.platform)
        else: selftest()
    except Exception:
        # No traceback, API response body, paths, file content or secrets in PUBLIC logs.
        print("PREFLIGHT_FAIL: consult controlled internal diagnostics", file=sys.stderr)
        return 1
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
