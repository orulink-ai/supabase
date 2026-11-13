"""Cross-platform, secret-safe commands for the WatcheRobot Supabase stack."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
from urllib.parse import urlsplit


def read_env(path):
    """Read literal dotenv values; never execute or interpolate shell code."""
    values = {}
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key.strip().replace("_", "").isalnum():
            raise ValueError("Invalid environment file entry")
        key, value = key.strip(), value.strip()
        if key in values:
            raise ValueError("Duplicate environment field: " + key)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def validate_env(env, region):
    if env.get("ACCOUNT_REGION") != region:
        raise ValueError("ACCOUNT_REGION does not match the requested deployment")
    for key in ("SUPABASE_PUBLIC_URL", "API_EXTERNAL_URL", "SITE_URL"):
        url = urlsplit(env.get(key, ""))
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError(key + " must be an HTTPS URL without credentials")
    public_url = env["SUPABASE_PUBLIC_URL"].rstrip("/")
    if env["API_EXTERNAL_URL"].rstrip("/") != public_url + "/auth/v1":
        raise ValueError("API_EXTERNAL_URL must use this project's Auth endpoint")
    if env["SITE_URL"].rstrip("/") != public_url:
        raise ValueError("SITE_URL must use this project's public URL")
    for key in ("POSTGRES_PASSWORD", "JWT_SECRET", "DASHBOARD_PASSWORD"):
        value = env.get(key, "")
        if len(value) < 32 or any(word in value.lower() for word in ("your-", "example", "insecure", "change-me")):
            raise ValueError("Missing or unsafe deployment secret: " + key)
    for key in ("ANON_KEY", "SERVICE_ROLE_KEY", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_ADMIN_EMAIL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_SECRET_KEY"):
        if not env.get(key):
            raise ValueError("Missing environment field: " + key)
    if env["ANON_KEY"] == env["SERVICE_ROLE_KEY"]:
        raise ValueError("Anonymous and service-role keys must be different")
    for key in ("ENABLE_EMAIL_AUTOCONFIRM", "ENABLE_PHONE_SIGNUP"):
        if env.get(key) != "false":
            raise ValueError(key + " must remain false")
    try:
        signing_keys = json.loads(env.get("JWT_KEYS", "[]"))
        verification_keys = json.loads(env.get("JWT_JWKS", "{}"))
        if not isinstance(signing_keys, list) or not signing_keys or not verification_keys.get("keys"):
            raise ValueError("Asymmetric signing and verification keys are required")
    except (json.JSONDecodeError, AttributeError) as error:
        raise ValueError("Invalid asymmetric key configuration") from error


def validate_compose(document):
    services = document.get("services", {})
    for name in ("db", "auth", "api-gw", "supavisor", "account-email-templates"):
        if name not in services:
            raise ValueError("Missing deployment service: " + name)
    for name, service in services.items():
        image = service.get("image", "")
        if "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
            raise ValueError("Service image must use a fixed version: " + name)
        ports = service.get("ports", [])
        if name in ("db", "supavisor", "account-email-templates") and ports:
            raise ValueError("Internal service must not publish ports: " + name)
        for port in ports:
            if not isinstance(port, dict) or port.get("host_ip") not in ("127.0.0.1", "::1"):
                raise ValueError("Published service must bind to loopback: " + name)
    auth = services["auth"].get("environment", {})
    expected = {
        "GOTRUE_MAILER_AUTOCONFIRM": "false",
        "GOTRUE_EXTERNAL_PHONE_ENABLED": "false",
        "GOTRUE_PASSWORD_MIN_LENGTH": "8",
        "GOTRUE_MAILER_OTP_EXP": "900",
        "GOTRUE_SMTP_MAX_FREQUENCY": "60s",
        "GOTRUE_MAILER_TEMPLATES_CONFIRMATION": "http://account-email-templates:8000/confirmation.html",
        "GOTRUE_MAILER_TEMPLATES_RECOVERY": "http://account-email-templates:8000/recovery.html",
    }
    for key, value in expected.items():
        if str(auth.get(key)) != value:
            raise ValueError("Incorrect Auth policy: " + key)
    if not services["account-email-templates"].get("read_only"):
        raise ValueError("Email template service must be read-only")
    for name, key in (("auth", "GOTRUE_JWT_KEYS"), ("realtime", "API_JWT_JWKS"), ("storage", "JWT_JWKS"), ("functions", "SUPABASE_JWKS")):
        value = services.get(name, {}).get("environment", {}).get(key, "")
        try:
            keys = json.loads(value)
            keys = keys if isinstance(keys, list) else keys.get("keys", [])
            if not keys:
                raise ValueError("Asymmetric verification is not configured: " + name)
        except (json.JSONDecodeError, AttributeError, TypeError) as error:
            raise ValueError("Invalid asymmetric verification configuration: " + name) from error


def ensure_region(repo, region, create=True):
    """A checkout's upstream bind mounts belong to exactly one region."""
    marker = Path(repo) / "deployments" / "watcherobot" / "private" / "deployment-region"
    if marker.exists():
        if marker.read_text(encoding="utf-8").strip() != region:
            raise ValueError("This checkout already belongs to another region; use an independent checkout and data volumes")
        return
    if create:
        marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with marker.open("x", encoding="utf-8") as output:
                output.write(region + "\n")
        except FileExistsError:
            ensure_region(repo, region, create=False)


def compose_command(repo, env_file, region):
    repo = Path(repo)
    return [
        "docker", "compose", "--env-file", str(env_file),
        "--project-directory", str(repo / "docker"),
        "-p", "watcherobot-" + region,
        "-f", str(repo / "docker" / "docker-compose.yml"),
        "-f", str(repo / "deployments" / "watcherobot" / "compose.override.yml"),
    ]


def protect_backup(path):
    """Make the empty backup private before writing any database bytes."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    # A protected DACL grants Full Control to this newly created file's owner only.
    if not convert("D:P(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not set_security(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def backup_database(command, destination, environment=None):
    """Publish a private dump only after pg_dumpall succeeds; never overwrite."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Backup destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".dump-", delete=False) as output:
            temporary = Path(output.name)
            protect_backup(temporary)
            result = subprocess.run(
                command + ["exec", "-T", "db", "pg_dumpall", "--clean", "--if-exists", "--quote-all-identifiers", "-U", "postgres"],
                stdout=output, stderr=subprocess.PIPE, check=False, env=environment,
            )
        if result.returncode != 0 or temporary.stat().st_size == 0:
            raise RuntimeError("Database backup failed; incomplete dump was not published")
        os.link(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def renew_certificate(acme_home, domain, addresses=None):
    """Renew through direct CA egress, restoring every temporary NAT rule."""
    if addresses is None:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(
            "acme-v02.api.letsencrypt.org", 443, socket.AF_INET, socket.SOCK_STREAM
        )})
    if not addresses or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).version != 4 for ip in addresses):
        raise ValueError("ACME DNS must resolve to public IPv4 addresses")
    added = []
    try:
        for address in addresses:
            rule = ["OUTPUT", "-d", address, "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", "watcherobot-acme-" + str(os.getpid()), "-j", "RETURN"]
            subprocess.run(["iptables", "--wait", "10", "-t", "nat", "-I", rule[0], "1"] + rule[1:], capture_output=True, check=True)
            added.append(rule)
        environment = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
        result = subprocess.run([
            str(Path(acme_home) / "acme.sh"), "--renew", "-d", domain,
            "--ecc", "--home", str(acme_home), "--server", "letsencrypt",
        ], env=environment, timeout=600, check=False)
        # acme.sh returns 2 when a certificate is not yet due for renewal.
        if result.returncode not in (0, 2):
            raise RuntimeError("ACME renewal failed")
    finally:
        cleanup_failed = False
        for rule in reversed(added):
            for attempt in range(3):
                result = subprocess.run(["iptables", "--wait", "10", "-t", "nat", "-D"] + rule, capture_output=True, check=False)
                if result.returncode == 0:
                    break
            cleanup_failed = cleanup_failed or result.returncode != 0
        if cleanup_failed:
            raise RuntimeError("Could not remove a temporary ACME egress rule")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "up", "status", "backup", "renew-certificate"))
    parser.add_argument("--region", choices=("cn", "global"), default="cn")
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--backup-file", type=Path)
    parser.add_argument("--acme-home", type=Path, default=Path.home() / ".acme.sh")
    args = parser.parse_args(argv)
    try:
        env_path = args.env_file.resolve()
        if os.name != "nt" and env_path.stat().st_mode & 0o077:
            raise ValueError("Private environment file must use permissions 0600")
        values = read_env(env_path)
        validate_env(values, args.region)
        if args.action == "renew-certificate":
            if not sys.platform.startswith("linux") or os.geteuid() != 0:
                raise ValueError("Certificate renewal requires the Linux deployment host's root account")
            renew_certificate(args.acme_home, urlsplit(values["SUPABASE_PUBLIC_URL"]).hostname)
            print("Certificate renewal check completed; temporary egress rules removed")
            return 0
        environment = dict(os.environ, **values)
        repo = Path(__file__).resolve().parents[3]
        ensure_region(repo, args.region, create=False)
        command = compose_command(repo, env_path, args.region)
        # Render privately: resolved Compose contains database/SMTP/JWT secrets.
        result = subprocess.run(command + ["config", "--format", "json"], capture_output=True, text=True, check=False, env=environment)
        if result.returncode:
            raise RuntimeError("Compose configuration failed; secret-bearing output was suppressed")
        validate_compose(json.loads(result.stdout))
        if args.action == "validate":
            print("Deployment configuration verified for " + args.region)
            return 0
        if args.action == "backup":
            if args.backup_file is None:
                raise ValueError("backup requires --backup-file")
            backup_database(command, args.backup_file, environment)
            print("Private database backup completed")
            return 0
        operation = ["up", "-d", "--wait", "--wait-timeout", "300"] if args.action == "up" else ["ps"]
        if args.action == "up":
            ensure_region(repo, args.region)
        return subprocess.run(command + operation, check=False, env=environment).returncode
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        # Do not interpolate configuration values or a CalledProcessError.
        print("Deployment error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
