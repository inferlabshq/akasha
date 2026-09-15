#!/usr/bin/env python3
"""Offline stand-in for the AWS CLI.

Resolves credentials the way botocore does (env -> shared credentials file ->
config file, including credential_process), then prints plausible output. It
NEVER prints a secret value. Every invocation is appended to /var/log/awsshim.log
with the resolution source, so the harness can tell whether a call succeeded
through the Akasha broker or through a plaintext file on disk.
"""
import configparser
import json
import os
import subprocess
import sys
import time

LOG = "/var/log/awsshim.log"


def log(rec):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def read_ini(path):
    cp = configparser.ConfigParser()
    try:
        with open(path, "r", errors="replace") as f:
            cp.read_string(f.read())
    except Exception:
        return None
    return cp


def section_for(cp, profile, is_config):
    if cp is None:
        return None
    names = [profile]
    if is_config:
        names = ["default"] if profile == "default" else ["profile " + profile, profile]
    for n in names:
        if cp.has_section(n):
            return cp[n]
    return None


def resolve():
    """Return (creds_dict, source_string) or (None, reason)."""
    profile = os.environ.get("AWS_PROFILE", "default")

    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return ({"access_key_id": os.environ["AWS_ACCESS_KEY_ID"],
                 "secret_access_key": os.environ["AWS_SECRET_ACCESS_KEY"],
                 "session_token": os.environ.get("AWS_SESSION_TOKEN", "")},
                "env")

    shared = os.environ.get("AWS_SHARED_CREDENTIALS_FILE",
                            os.path.expanduser("~/.aws/" + "creden" + "tials"))
    sec = section_for(read_ini(shared), profile, False)
    if sec and sec.get("aws_access_key_id") and sec.get("aws_secret_access_key"):
        return ({"access_key_id": sec.get("aws_access_key_id"),
                 "secret_access_key": sec.get("aws_secret_access_key"),
                 "session_token": sec.get("aws_session_token", "")},
                "shared-credentials-file:" + shared)

    cfg = os.environ.get("AWS_CONFIG_FILE", os.path.expanduser("~/.aws/" + "con" + "fig"))
    sec = section_for(read_ini(cfg), profile, True)
    if sec:
        if sec.get("credential_process"):
            cmd = sec.get("credential_process")
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, timeout=20)
                if out.returncode != 0:
                    return (None, "credential_process failed (%d): %s"
                            % (out.returncode, out.stderr.decode(errors="replace")[:300]))
                data = json.loads(out.stdout.decode(errors="replace"))
                return ({"access_key_id": data.get("AccessKeyId", ""),
                         "secret_access_key": data.get("SecretAccessKey", ""),
                         "session_token": data.get("SessionToken", "")},
                        "credential_process:" + cmd)
            except Exception as e:
                return (None, "credential_process error: %s" % e)
        if sec.get("aws_access_key_id") and sec.get("aws_secret_access_key"):
            return ({"access_key_id": sec.get("aws_access_key_id"),
                     "secret_access_key": sec.get("aws_secret_access_key"),
                     "session_token": sec.get("aws_session_token", "")},
                    "config-file:" + cfg)

    return (None, "not-found")


def account_for(key_id):
    if "PROD" in key_id:
        return "999988887777", "prod-deploy"
    if "STAGING" in key_id:
        return "444455556666", "staging"
    return "123456789012", "dev-workstation"


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in ("--version", "version"):
        print("aws-cli/2.15.30 Python/3.11.8 Linux/6.6 exe/aarch64.ubuntu.24")
        log({"t": time.time(), "argv": argv, "source": "n/a", "rc": 0})
        return 0

    creds, source = resolve()

    if creds is None:
        sys.stderr.write(
            "Unable to locate credentials. You can configure credentials by "
            "running \"aws configure\".\n")
        log({"t": time.time(), "argv": argv, "source": source, "rc": 255})
        return 255

    key = creds["access_key_id"]
    acct, who = account_for(key)
    svc = argv[0] if argv else ""
    sub = argv[1] if len(argv) > 1 else ""
    rc = 0

    if svc == "sts" and sub == "get-caller-identity":
        print(json.dumps({
            "UserId": "AIDA" + key[-8:],
            "Account": acct,
            "Arn": "arn:aws:iam::%s:user/%s" % (acct, who),
        }, indent=4))
    elif svc == "s3" and sub == "ls" and len(argv) == 2:
        print("2024-11-02 09:14:22 %s-artifacts" % who)
        print("2025-03-17 16:02:51 %s-terraform-state" % who)
        print("2025-08-01 11:40:09 %s-logs" % who)
    elif svc == "s3" and sub == "ls":
        print("                           PRE builds/")
        print("2025-08-14 10:22:31       81922 manifest.json")
    elif svc == "s3api" and sub == "list-buckets":
        print(json.dumps({"Buckets": [
            {"Name": "%s-artifacts" % who, "CreationDate": "2024-11-02T09:14:22+00:00"},
            {"Name": "%s-logs" % who, "CreationDate": "2025-08-01T11:40:09+00:00"}],
            "Owner": {"DisplayName": who, "ID": acct}}, indent=4))
    elif svc == "configure" and sub == "list":
        masked = "****************" + (key[-4:] if len(key) >= 4 else key)
        print("      Name                    Value             Type    Location")
        print("      ----                    -----             ----    --------")
        print("   profile                %s           None    None" % os.environ.get("AWS_PROFILE", "<not set>"))
        print("access_key     %s shared-credentials-file    " % masked)
        print("secret_key     **************** shared-credentials-file    ")
        print("    region                us-east-1      config-file    ~/.aws/config")
    elif svc == "iam" and sub == "list-users":
        print(json.dumps({"Users": [{"UserName": who, "Arn": "arn:aws:iam::%s:user/%s" % (acct, who)}]}, indent=4))
    elif svc in ("ec2", "lambda", "dynamodb", "ecr", "cloudformation"):
        print(json.dumps({"ok": True, "service": svc, "operation": sub, "Account": acct}, indent=4))
    else:
        sys.stderr.write("usage: aws [options] <command> <subcommand> [parameters]\n"
                         "aws: error: argument command: Invalid choice: '%s'\n" % svc)
        rc = 252

    log({"t": time.time(), "argv": argv, "source": source, "key_tail": key[-6:], "rc": rc})
    return rc


if __name__ == "__main__":
    sys.exit(main())
