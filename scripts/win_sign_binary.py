import os
import sys
import pathlib
import requests


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: win_sign_binary.py <path-to-exe>", file=sys.stderr)
        return 2

    signer_url = os.environ.get("bamboo_signerUrl") or os.environ.get("SIGNER_URL")
    api_key = os.environ.get("bamboo_trustTunnelWinSignerSecretApiKey") or os.environ.get("SIGNER_API_KEY")

    if not signer_url:
        print("bamboo_signerUrl is not set", file=sys.stderr)
        return 2
    if not api_key:
        print("bamboo_trustTunnelWinSignerSecretApiKey is not set", file=sys.stderr)
        return 2

    in_path = pathlib.Path(sys.argv[1])
    if not in_path.exists():
        print(f"File not found: {in_path}", file=sys.stderr)
        return 2

    out_path = in_path.with_suffix(in_path.suffix + ".signed")

    try:
        with in_path.open("rb") as f:
            files = {"file": (in_path.name, f)}
            r = requests.post(
                signer_url,
                headers={"Authorization": f"Bearer {api_key}"},
                files=files,
                timeout=300,
            )
    except Exception as e:
        print(f"Signing request failed for {in_path}: {e}", file=sys.stderr)
        return 1

    if r.status_code < 200 or r.status_code >= 300:
        print(
            f"Signing failed for {in_path}. Status={r.status_code} Body={r.text}",
            file=sys.stderr,
        )
        return 1

    try:
        out_path.write_bytes(r.content)
        out_path.replace(in_path)
    except Exception as e:
        print(f"Failed to write signed file for {in_path}: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
