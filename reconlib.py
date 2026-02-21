import os
import json
from datetime import datetime, timezone
import ipaddress
import re
import subprocess
import shutil
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

TOOL_NAME = "SPECTER-RECON"
TOOL_AUTHOR = "Made by Aref Turkieh"

def safe_name(s: str) -> str:
    s = (s or "").strip().lower()

    # remove scheme if user pasted a URL
    for prefix in ("http://", "https://"):
        if s.startswith(prefix):
            s = s[len(prefix):]

    # replace common bad characters
    bad = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ']
    for ch in bad:
        s = s.replace(ch, "_")

    # collapse repeated underscores
    while "__" in s:
        s = s.replace("__", "_")

    s = s.strip("_")
    return s[:80] if len(s) > 80 else (s or "target")


def utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%SZ")


def normalize_target(raw: str) -> str:

    s = (raw or "").strip().lower()

    # strip scheme
    for prefix in ("http://", "https://"):
        if s.startswith(prefix):
            s = s[len(prefix):]

    # strip path
    if "/" in s:
        s = s.split("/", 1)[0]

    # strip trailing dot
    s = s.strip().strip(".")

    # strip :port if not ipv6 (ipv6 has multiple colons)
    if s.count(":") == 1:
        host, maybe_port = s.split(":", 1)
        if maybe_port.isdigit():
            s = host

    return s

# ---- step 2 checks whether its domain or ip ----
def classify_target(raw: str) -> dict:

    t = normalize_target(raw)

    if not t:
        return {"type": "invalid", "ip": None, "domain": None, "reason": "empty"}

    # Try IP
    try:
        ip = ipaddress.ip_address(t)
        return {
            "type": "ip",
            "ip": str(ip),
            "domain": None,
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_link_local": ip.is_link_local,
            "is_reserved": ip.is_reserved,
            "is_multicast": ip.is_multicast,
        }
    except ValueError:
        pass

    if " " in t:
        return {"type": "invalid", "ip": None, "domain": None, "reason": "space_in_target"}

    if len(t) > 253:
        return {"type": "invalid", "ip": None, "domain": None, "reason": "too_long"}

    if not re.fullmatch(r"[a-z0-9.-]+", t):
        return {"type": "invalid", "ip": None, "domain": None, "reason": "bad_chars"}

    labels = t.split(".")
    if len(labels) < 2:
        return {"type": "invalid", "ip": None, "domain": None, "reason": "no_dot"}

    for lab in labels:
        if not lab:
            return {"type": "invalid", "ip": None, "domain": None, "reason": "empty_label"}
        if len(lab) > 63:
            return {"type": "invalid", "ip": None, "domain": None, "reason": "label_too_long"}
        if lab.startswith("-") or lab.endswith("-"):
            return {"type": "invalid", "ip": None, "domain": None, "reason": "hyphen_edge"}

    return {"type": "domain", "ip": None, "domain": t}


def is_blocked_ip(ip_str: str, allow_private: bool) -> tuple[bool, str]:
    ip = ipaddress.ip_address(ip_str)

    if ip.is_loopback:
        return True, "loopback"
    if ip.is_link_local:
        return True, "link_local"
    if ip.is_multicast:
        return True, "multicast"
    if ip.is_reserved:
        return True, "reserved"
    if ip.is_private and not allow_private:
        return True, "private_not_allowed"

    return False, ""


def load_targets(single_target: str | None, file_path: str | None) -> list[str]:
    targets: list[str] = []

    if single_target:
        t = single_target.strip()
        if t:
            targets.append(t)

    elif file_path:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Targets file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                targets.append(t)

    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique
#-------- end for step 2 -------

#---- Helpers-----
def make_base_run_dirs(out_base: str, run_label: str) -> tuple[str, str]:
    os.makedirs(out_base, exist_ok=True)
    run_id = utc_run_id()
    run_dir = os.path.join(out_base, f"{safe_name(run_label)}__{run_id}")
    os.makedirs(run_dir, exist_ok=True)
    return run_id, run_dir


def make_single_target_dirs(out_base: str, target: str) -> tuple[str, str, str]:
  
    run_id, run_dir = make_base_run_dirs(out_base, target)
    raw_dir = os.path.join(run_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    return run_id, run_dir, raw_dir


def make_batch_dirs(out_base: str, label: str = "batch") -> tuple[str, str, str]:

    run_id, run_dir = make_base_run_dirs(out_base, label)
    targets_root = os.path.join(run_dir, "targets")
    os.makedirs(targets_root, exist_ok=True)
    return run_id, run_dir, targets_root


def make_target_dirs_in_batch(targets_root: str, target: str) -> tuple[str, str]:

    target_dir = os.path.join(targets_root, safe_name(target))
    raw_dir = os.path.join(target_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    return target_dir, raw_dir

#---- variables -----
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

WEB_PORT_SCHEMES = {
    80: "http",
    8080: "http",
    8000: "http",
    8888: "http",
    443: "https",
    8443: "https"
}

SMB_PORTS = set([445, 139])
#-----end of vars-----
def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

def make_clean_wordlist(src_path: str, dst_path: str) -> dict:
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    total = 0
    kept = 0

    with open(src_path, "r", encoding="utf-8", errors="ignore") as f_in, \
         open(dst_path, "w", encoding="utf-8") as f_out:
        for line in f_in:
            total += 1
            w = line.strip()
            if not w:
                continue
            if w.startswith("#") or w.startswith("//") or w.startswith(";"):
                continue
            if w == "#" or w.startswith("# "):
                continue
            if any(c.isspace() for c in w):
                continue

            f_out.write(w + "\n")
            kept += 1

    return {"src": src_path, "dst": dst_path, "total_lines": total, "kept": kept}

def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line.rstrip("\n") + "\n")
def tool_dirs(raw_root: str, tool: str) -> tuple[str, str]:
    tool_root = os.path.join(raw_root, tool)
    tool_raw = os.path.join(tool_root, "raw")
    tool_clean = os.path.join(tool_root, "clean")
    os.makedirs(tool_raw, exist_ok=True)
    os.makedirs(tool_clean, exist_ok=True)
    return tool_raw, tool_clean

#---- end of helpers ----


#----- report and terminal helpers ----
# -------------------- helpers --------------------
def _read_text(path: str, max_bytes: int = 400_000) -> str:
    if not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(max_bytes)

def _read_json(path: str):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None

def _safe_list(x):
    return x if isinstance(x, list) else []

def _safe_dict(x):
    return x if isinstance(x, dict) else {}

def _first_existing(*paths: str) -> str | None:
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None

def _md_code_block(text: str) -> str:
    text = text.rstrip()
    return f"```text\n{text}\n```\n" if text else "_(empty)_\n"

def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

# -------------------- report generation --------------------
def generate_report_md(tr: dict, out_md: str) -> dict:
    os.makedirs(os.path.dirname(out_md), exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    modules = _safe_dict(tr.get("modules"))
    parsed = _safe_dict(tr.get("parsed"))
    paths = _safe_dict(tr.get("paths"))
    raw_dir = paths.get("raw_dir", "")

    target_label = tr.get("input") or tr.get("domain") or tr.get("ip") or "target"

    lines = []
    lines.append(f"# Recon Report: `{target_label}`")
    lines.append("")
    lines.append(f"- Generated: **{now}**")
    lines.append(f"- Type: `{tr.get('type', 'unknown')}`")
    if tr.get("domain"):
        lines.append(f"- Domain: `{tr['domain']}`")
    if tr.get("ip"):
        lines.append(f"- IP: `{tr['ip']}`")
    if tr.get("resolved_ips"):
        lines.append(f"- Resolved IPs: {', '.join(map(str, tr['resolved_ips']))}")
    lines.append("")

    # 1) crt.sh
    lines.append("## 1) crt.sh Findings")
    crt = _safe_dict(modules.get("crtsh"))
    crt_json = _safe_dict(crt.get("artifacts")).get("crtsh_json")
    if crt.get("status") == "ok" and crt_json and os.path.exists(crt_json):
        data = _read_json(crt_json)
        # your crtsh.json might be a list of strings or objects; support both
        found = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    found.append(item)
                elif isinstance(item, dict):
                    # common key names people use
                    for k in ("name_value", "name", "domain", "subdomain"):
                        if k in item and isinstance(item[k], str):
                            found.append(item[k])
                            break
        found = sorted(set(found))
        lines.append(f"- Count: **{len(found)}**")
        if found:
            preview = "\n".join(found[:50])
            lines.append("")
            lines.append(_md_code_block(preview))
        else:
            lines.append("")
            lines.append("_(No subdomains extracted from crtsh.json)_")
    else:
        lines.append("_(crt.sh was skipped or no output found.)_")
    lines.append("")

    # 2) Port scan summary
    lines.append("## 2) Port Scan (Open Ports)")
    ports = _safe_dict(tr.get("ports"))
    if ports:
        for host, plist in ports.items():
            plist = sorted(set(_safe_list(plist)))
            lines.append(f"- `{host}`: {', '.join(map(str, plist)) if plist else '(none)'}")
    else:
        lines.append("_(No ports object found.)_")
    lines.append("")

    # 3) Nmap full output (txt)
    lines.append("## 3) Nmap Scan Output")
    nmap = _safe_dict(modules.get("nmap"))
    nmap_txt = _safe_dict(nmap.get("artifacts")).get("nmap_txt")
    nmap_txt = _first_existing(nmap_txt, os.path.join(raw_dir, "nmap.txt"))
    if nmap_txt:
        lines.append(f"- File: `{nmap_txt}`")
        lines.append("")
        lines.append(_md_code_block(_read_text(nmap_txt)))
    else:
        lines.append("_(No nmap txt output found.)_")
    lines.append("")

    # 4) ffuf findings (from parsed dirs txt)
    lines.append("## 4) FFUF Findings (Directories/Paths)")
    ffuf_p = _safe_dict(parsed.get("ffuf"))
    if ffuf_p.get("status") == "ok":
        items = _safe_list(ffuf_p.get("items"))
        total = _safe_dict(ffuf_p.get("counts")).get("total_dirs")
        lines.append(f"- Total dirs (all web targets): **{total if total is not None else 'unknown'}**")
        for it in items:
            out_txt = it.get("out_txt")
            url_src = it.get("ffuf_json") or it.get("url") or ""
            if out_txt and os.path.exists(out_txt):
                lines.append(f"\n**Source:** `{url_src}`")
                lines.append(f"- Clean dirs file: `{out_txt}`")
                lines.append("")
                lines.append(_md_code_block(_read_text(out_txt, max_bytes=200_000)))
    else:
        lines.append("_(ffuf parsing missing/skipped.)_")
    lines.append("")

    # 5) gau (only point to clean file)
    lines.append("## 5) GAU Results")
    gau_p = _safe_dict(parsed.get("gau"))
    if gau_p.get("status") == "ok":
        artifacts = _safe_dict(gau_p.get("artifacts"))
        lines.append(f"- In-scope clean URLs: `{artifacts.get('gau_clean_txt','(missing)')}`")
        lines.append(f"- External URLs: `{artifacts.get('gau_external_txt','(missing)')}`")
        counts = _safe_dict(gau_p.get("counts"))
        if counts:
            lines.append(f"- Counts: in-scope={counts.get('in_scope',0)}, external={counts.get('external',0)}")
    else:
        lines.append("_(gau parsing missing/skipped.)_")
    lines.append("")

    # 6) gospider (only point to clean files)
    lines.append("## 6) GoSpider Results")
    gs_p = _safe_dict(parsed.get("gospider"))
    if gs_p.get("status") == "ok":
        artifacts = _safe_dict(gs_p.get("artifacts"))
        url_txts = _safe_list(artifacts.get("url_txts"))
        total_urls = _safe_dict(gs_p.get("counts")).get("total_urls")
        lines.append(f"- Total URLs (all runs): **{total_urls if total_urls is not None else 'unknown'}**")
        if url_txts:
            lines.append("- Clean URL files:")
            for p in url_txts:
                lines.append(f"  - `{p}`")
    else:
        lines.append("_(gospider parsing missing/skipped.)_")
    lines.append("")

    # 7) SMB (your future module)
    lines.append("## 7) SMB Info")
    smb = _safe_dict(modules.get("smb"))
    if smb.get("status") == "ok":
        art = _safe_dict(smb.get("artifacts"))
        smb_txt = art.get("smb_summary_txt")
        lines.append(f"- Summary file: `{smb_txt}`")
        if smb_txt and os.path.exists(smb_txt):
            lines.append("")
            lines.append(_md_code_block(_read_text(smb_txt)))
    else:
        lines.append("_(SMB module not run yet / skipped.)_")

    report = "\n".join(lines).rstrip() + "\n"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(report)

    return {"status": "ok", "out_md": out_md, "bytes": len(report.encode("utf-8"))}


def _read_text_file(path: str, max_bytes: int = 400_000) -> tuple[str, bool]:
    if not path or not os.path.exists(path):
        return "", False
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    try:
        return data.decode("utf-8", errors="replace"), truncated
    except Exception:
        return str(data), truncated


def _print_section(title: str):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

# -------------------- terminal printer (linpeas-ish) --------------------

def print_banner():
    banner = r"""
            ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
            ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
            ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
            ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
            ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
            ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                                S P E C T E R - R E C O N
                                Advanced Recon Framework
                """
    print(banner)
    
    VERSION = "v1.0.0"
    print(f"{TOOL_AUTHOR} | {VERSION}")
    print("=" * 70)

def print_terminal_report(tr: dict) -> None:
    target_label = tr.get("domain") or tr.get("ip") or tr.get("input") or "target"
    paths = tr.get("paths", {}) or {}
    raw_dir = paths.get("raw_dir", "")
    report_md = (tr.get("artifacts", {}) or {}).get("report_md")

    print()
    print(f"Run ID: {tr.get('run_id')}")
    print(f"Target: {target_label}")
    if report_md:
        print(f"Report (md): {report_md}")
    if paths.get("target_summary_json"):
        print(f"Target summary: {paths['target_summary_json']}")
    if raw_dir:
        print(f"Raw dir: {raw_dir}")

    modules = tr.get("modules", {}) or {}
    parsed = tr.get("parsed", {}) or {}

    # [1] crtsh
    _print_section("[1] CRT.SH")
    crt = modules.get("crtsh", {})
    if crt.get("status") == "ok":
        print(f"- subdomains: {crt.get('counts', {}).get('subdomains', 0)}")
        print(f"- file: {crt.get('artifacts', {}).get('subdomains_txt')}")
    else:
        print("- skipped/missing")

    # [2] open ports
    _print_section("[2] OPEN PORTS")
    ports = tr.get("ports", {}) or {}
    if not ports:
        print("- none")
    else:
        for ip, plist in ports.items():
            print(f"- {ip}: {', '.join(str(p) for p in plist)}")

    # [3] nmap (print full scan output)
    _print_section("[3] NMAP (FULL OUTPUT)")
    nmap_mod = modules.get("nmap", {})
    nmap_txt = (nmap_mod.get("artifacts", {}) or {}).get("nmap_txt")
    if nmap_txt and os.path.exists(nmap_txt):
        content, truncated = _read_text_file(nmap_txt)
        print(content.rstrip())
        if truncated:
            print("\n[!] Nmap output truncated (too large). See file for full output:")
            print(f"    {nmap_txt}")
    else:
        print("- missing")

    # [4] ffuf
    _print_section("[4] FFUF")
    ff = parsed.get("ffuf", {})
    if ff.get("status") == "ok":
        total_dirs = (ff.get("counts", {}) or {}).get("total_dirs", 0)
        print(f"- parsed ok | total_dirs: {total_dirs}")
        for p in (ff.get("artifacts", {}) or {}).get("dir_txts", []):
            print(f"  - {p}")
    else:
        print("- skipped/missing")

    # [5] gau
    _print_section("[5] GAU")
    g = parsed.get("gau", {})
    if g.get("status") == "ok":
        arts = g.get("artifacts", {}) or {}
        print(f"- clean:    {arts.get('gau_clean_txt')}")
        print(f"- external: {arts.get('gau_external_txt')}")
    else:
        print("- skipped/missing")

    # [6] gospider
    _print_section("[6] GOSPIDER")
    gs = parsed.get("gospider", {})
    if gs.get("status") == "ok":
        url_txts = (gs.get("artifacts", {}) or {}).get("url_txts", [])
        print(f"- url_files: {len(url_txts)}")
        for p in url_txts:
            print(f"  - {p}")
    else:
        print("- skipped/missing")

    # [7] smb (show report + file)
    _print_section("[7] SMB")
    smb_mod = modules.get("smb", {})
    smb_parsed = parsed.get("smb", {})
    if smb_mod.get("status") in ("ok", "error"):
        arts = smb_mod.get("artifacts", {}) or {}
        print(f"- status: {smb_mod.get('status')}")
        if arts.get("smb_summary_txt"):
            print(f"- smb report: {arts.get('smb_summary_txt')}")
        if arts.get("smb_stdout_txt"):
            print(f"- smbclient output: {arts.get('smb_stdout_txt')}")
    elif smb_parsed.get("status") == "ok":
        arts = smb_parsed.get("artifacts", {}) or {}
        print(f"- smb report: {arts.get('smb_summary_txt')}")
    else:
        print("- skipped/missing")

    print()
#----- end of report and terminal helpers -----


# --- step 3 run crt.sh for domain, parse subdomains and resolve them into ips, then store raw outputs and update target summary and summary json ----

def run_cmd(cmd_list: list[str], out_path: str, err_path: str, timeout: int = 60) -> int:

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(os.path.dirname(err_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8", errors="ignore") as out_f, \
         open(err_path, "w", encoding="utf-8", errors="ignore") as err_f:
        try:
            cp = subprocess.run(
                cmd_list,
                stdout=out_f,
                stderr=err_f,
                text=True,
                timeout=timeout,
                check=False
            )
            return cp.returncode
        except subprocess.TimeoutExpired:
            err_f.write(f"\n[!] Timeout after {timeout}s\n")
            return 124
        except Exception as e:
            err_f.write(f"\n[!] Exception: {e}\n")
            return 1


def crtsh_enum(domain: str, raw_json_path: str, subs_txt_path: str, timeout: int = 60) -> list[str]:

    err_path = raw_json_path + ".err"

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    rc = run_cmd(["curl", "-sS", url], raw_json_path, err_path, timeout=timeout)

    if not os.path.isfile(raw_json_path) or os.path.getsize(raw_json_path) == 0:
        with open(subs_txt_path, "w", encoding="utf-8") as f:
            f.write("")
        return []

    try:
        with open(raw_json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        with open(subs_txt_path, "w", encoding="utf-8") as f:
            f.write("")
        return []

    subs = set()
    domain = domain.lower().strip().strip(".")

    for rec in data if isinstance(data, list) else []:
        nv = rec.get("name_value")
        if not nv:
            continue
        for name in str(nv).splitlines():
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            name = name.strip().strip(".")
            if name == domain or name.endswith("." + domain):
                subs.add(name)

    out = sorted(subs)
    os.makedirs(os.path.dirname(subs_txt_path), exist_ok=True)
    with open(subs_txt_path, "w", encoding="utf-8") as f:
        for s in out:
            f.write(s + "\n")

    return out



def _extract_ips_from_lines(lines: list[str]) -> list[str]:
    ips = []
    for line in lines:
        v = line.strip()
        if not v:
            continue
        # keep only valid IP addresses
        try:
            ipaddress.ip_address(v)
            ips.append(v)
        except ValueError:
            continue
    # de-dup preserve order
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def resolve_hosts(
    hosts: list[str],
    raw_resolved_txt: str,
    resolve_json_path: str,
    timeout_per_host: int = 3
) -> tuple[dict, list[str]]:
    os.makedirs(os.path.dirname(raw_resolved_txt), exist_ok=True)

    dig_path = shutil.which("dig")
    results: dict[str, list[str]] = {}
    unique_ips_set = set()
    unique_ips_list: list[str] = []

    def add_ip(ip: str):
        if ip not in unique_ips_set:
            unique_ips_set.add(ip)
            unique_ips_list.append(ip)

    with open(raw_resolved_txt, "w", encoding="utf-8") as out_f:
        for host in hosts:
            host_n = normalize_target(host)
            if not host_n:
                continue

            ips: list[str] = []

            if dig_path:
                rc, stdout, stderr = run_cmd_capture([dig_path, "+short", host_n], timeout=timeout_per_host)
                # parse each line as IP
                for line in stdout.splitlines():
                    v = line.strip()
                    if not v:
                        continue
                    try:
                        ipaddress.ip_address(v)
                        if v not in ips:
                            ips.append(v)
                    except ValueError:
                        continue
            else:
                # fallback: socket DNS
                try:
                    infos = socket.getaddrinfo(host_n, None)
                    for info in infos:
                        v = info[4][0]
                        try:
                            ipaddress.ip_address(v)
                            if v not in ips:
                                ips.append(v)
                        except ValueError:
                            continue
                except Exception:
                    ips = []

            results[host_n] = ips

            if ips:
                for ip in ips:
                    add_ip(ip)
                out_f.write(f"{host_n} -> {', '.join(ips)}\n")
            else:
                out_f.write(f"{host_n} -> \n")

    write_json(resolve_json_path, results)
    return results, unique_ips_list

#----- step 4 port scanner ----
def is_port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except Exception:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

def fast_portscan(ip: str, ports: list[int], threads: int, timeout: float, out_path: str) -> tuple[list[int], float]:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    t0 = time.time()
    open_ports: list[int] = []

    max_workers = max(1, min(int(threads), 500))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(is_port_open, ip, p, timeout): p for p in ports}

        for fut in as_completed(future_map):
            p = future_map[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass

    open_ports.sort()
    dt = time.time() - t0

    # write raw output
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"IP: {ip}\n")
        f.write(f"Scanned: {len(ports)} ports\n")
        if open_ports:
            f.write("Open: " + ",".join(str(p) for p in open_ports) + "\n")
        else:
            f.write("Open: \n")
        f.write(f"Duration: {dt:.3f}s\n")

    return open_ports, dt

def targeted_nmap(ip: str, open_ports: list[int], out_txt: str, out_xml: str, timeout: int = 600) -> int:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    if not open_ports:
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("No open ports found, skipping nmap.\n")
        with open(out_xml, "w", encoding="utf-8") as f:
            f.write("")
        with open(out_txt + ".err", "w", encoding="utf-8") as f:
            f.write("")
        return 0

    ports_str = ",".join(str(p) for p in open_ports)
    err_path = out_txt + ".err"

    cmd = ["nmap", "-T4", "-A", "-p", ports_str, ip, "-oN", out_txt, "-oX", out_xml]

    runner_out = out_txt + ".runner"
    rc = run_cmd(cmd, runner_out, err_path, timeout=timeout)

    try:
        if os.path.exists(runner_out):
            os.remove(runner_out)
    except Exception:
        pass

    return rc

#------ step 5 service routing ------
def build_services_from_ports(ports_dict: dict) -> dict:
    services = {"web": [], "smb": []}

    for ip, ports_list in ports_dict.items():
        if not isinstance(ports_list, list):
            continue

        for port in ports_list:
            if port in WEB_PORT_SCHEMES:
                scheme = WEB_PORT_SCHEMES[port]

                if scheme == "http" and port == 80:
                    url = f"http://{ip}"
                elif scheme == "https" and port == 443:
                    url = f"https://{ip}"
                else:
                    url = f"{scheme}://{ip}:{port}"

                services["web"].append({
                    "ip": ip,
                    "port": port,
                    "scheme": scheme,
                    "url": url
                })

            if port in SMB_PORTS:
                services["smb"].append({"ip": ip, "port": port})

    # Deduplicate WEB
    seen_web = set()
    web_unique = []
    for item in services["web"]:
        key = (item["ip"], item["port"], item["scheme"])
        if key not in seen_web:
            seen_web.add(key)
            web_unique.append(item)
    services["web"] = web_unique

    # Deduplicate SMB
    seen_smb = set()
    smb_unique = []
    for item in services["smb"]:
        key = (item["ip"], item["port"])
        if key not in seen_smb:
            seen_smb.add(key)
            smb_unique.append(item)
    services["smb"] = smb_unique

    # Stable sorting
    services["web"] = sorted(services["web"], key=lambda x: (x["ip"], x["port"]))
    services["smb"] = sorted(services["smb"], key=lambda x: (x["ip"], x["port"]))

    return services

# ------ step 6.1  curl precheck ----
def safe_tag_for_url(url: str) -> str:
    tag = url
    tag = tag.replace("://", "_")
    tag = tag.replace("/", "_")
    tag = tag.replace(":", "_")
    tag = tag.replace("?", "_")
    tag = tag.replace("&", "_")
    tag = tag.replace("=", "_")

    # collapse double underscores
    while "__" in tag:
        tag = tag.replace("__", "_")

    return tag.strip("_")

def curl_precheck(url: str, out_txt: str, timeout: int = 10) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    err_path = out_txt + ".err"

    cmd = [
        "curl",
        "-sS",
        "-I",           # headers only
        "-L",           # follow redirects
        "--max-time",
        str(timeout),
        url
    ]

    rc = run_cmd(cmd, out_txt, err_path, timeout=timeout + 2)

    status_code = None
    server = None

    # Parse output
    try:
        with open(out_txt, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Multiple HTTP blocks possible due to redirects
        for line in lines:
            line_strip = line.strip()

            # Status line
            if line_strip.startswith("HTTP/"):
                parts = line_strip.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])

            # Server header
            if line_strip.lower().startswith("server:"):
                server = line_strip.split(":", 1)[1].strip()

    except Exception:
        pass

    return {
        "url": url,
        "rc": rc,
        "status_code": status_code,
        "server": server
    }
#------ step 6.2 nikto -----
def run_nikto(url: str, out_txt: str, timeout: int = 1200) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    err_path = out_txt + ".err"

    cmd = [
        "nikto",
        "-h", url,
        "-Display", "V",
        "-nointeractive"
    ]
    rc = run_cmd(cmd, out_txt, err_path, timeout=timeout)
    return {
        "url": url,
        "rc": rc,
        "out_txt": out_txt,
        "err": err_path
    }

#------ step 6.3 ffuf -----
def run_ffuf(base_url: str, wordlist: str, threads: int, out_json: str, timeout: int = 1200) -> dict:
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    err_path = out_json + ".err"

    fuzz_url = base_url.rstrip("/") + "/FUZZ"
    t = max(1, min(int(threads), 500))

    clean_wordlist_path = out_json + ".wordlist.clean.txt"
    wl_meta = make_clean_wordlist(wordlist, clean_wordlist_path)

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", clean_wordlist_path,
        "-t", str(t),
        "-o", out_json,
        "-of", "json",
        "-mc", "200,204,301,302,307,401,403,405,500",
        "-fc", "404",
        "-ac"
    ]

    rc = run_cmd(cmd, out_path=out_json + ".runner", err_path=err_path, timeout=timeout)


    return {
        "url": base_url,
        "fuzz_url": fuzz_url,
        "rc": rc,
        "wordlist": wl_meta,
        "artifacts": {
            "ffuf_json": out_json,
            "stderr": err_path,
            "clean_wordlist": clean_wordlist_path,
        }
    }

#-----step 6.4 gau-----
def run_gau(domain: str, out_txt: str, out_dedup_txt: str, timeout: int = 1200) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)
    os.makedirs(os.path.dirname(out_dedup_txt), exist_ok=True)

    err_path = out_txt + ".err"

    cmd = ["gau", "--subs", domain]
    rc = run_cmd(cmd, out_path=out_txt, err_path=err_path, timeout=timeout)

    urls = []
    try:
        with open(out_txt, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u:
                    urls.append(u)

        urls = sorted(set(urls))

        with open(out_dedup_txt, "w", encoding="utf-8") as f:
            for u in urls:
                f.write(u + "\n")
    except Exception:
        pass

    return {
        "domain": domain,
        "rc": rc,
        "artifacts": {
            "gau_txt": out_txt,
            "gau_dedup_txt": out_dedup_txt,
            "stderr": err_path
        },
        "counts": {
            "dedup_urls": len(urls)
        }
    }

#----- step 6.5 gospider -----
def run_gospider(
    url: str,
    out_txt: str,
    threads: int,
    depth: int = 2,
    timeout: int = 900
) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    err_path = out_txt + ".err"

    t = max(1, min(int(threads), 100))

    cmd = [
        "gospider",
        "-s", url,
        "-c", str(t),
        "-d", str(depth),
        "--robots",
        "--js",
        "--include-subs"
    ]

    rc = run_cmd(cmd, out_txt, err_path, timeout=timeout)

    return {
        "url": url,
        "rc": rc,
        "artifacts": {
            "gospider_raw": out_txt,
            "stderr": err_path
        }
    }

# ---------------- Step 7.2 ffuf parsing ----------------
def parse_ffuf_json_to_dirs_txt(ffuf_json_path: str, out_txt: str) -> dict:
    
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    if not os.path.exists(ffuf_json_path):
        _write_lines(out_txt, [])
        return {"status": "missing", "ffuf_json": ffuf_json_path, "out_txt": out_txt, "count": 0}

    try:
        with open(ffuf_json_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        _write_lines(out_txt, [])
        return {"status": "error", "error": str(e), "ffuf_json": ffuf_json_path, "out_txt": out_txt, "count": 0}

    results = data.get("results", [])
    dirs: set[str] = set()

    for r in results:
        inp = r.get("input") or {}
        fuzz = inp.get("FUZZ")
        if not fuzz:
            continue

        fuzz = str(fuzz).strip()

        # Skip wordlist comments / junk that can appear as hits
        if not fuzz or fuzz.startswith("#"):
            continue

        # Normalize: remove leading slash
        while fuzz.startswith("/"):
            fuzz = fuzz[1:]

        # Keep it simple: we store the fuzz word as-is (dir name / path piece)
        if fuzz:
            dirs.add(fuzz)

    clean = sorted(dirs)
    _write_lines(out_txt, clean)

    return {"status": "ok", "ffuf_json": ffuf_json_path, "out_txt": out_txt, "count": len(clean)}


# ---------------- Step 7.2 GAU parsing ----------------
def parse_gau_to_txt(
    gau_in: str,
    gau_clean_out: str,
    out_external_txt: str = None,
    in_scope_hosts: list[str] = None
) -> dict:
    os.makedirs(os.path.dirname(gau_clean_out), exist_ok=True)
    if out_external_txt:
        os.makedirs(os.path.dirname(out_external_txt), exist_ok=True)

    in_scope_hosts = [h.lower() for h in (in_scope_hosts or []) if h]
    in_scope_set = set(in_scope_hosts)

    inscope = []
    external = []

    def host_ok(netloc: str) -> bool:
        # netloc can include port; keep it (you already add netlocs with ports)
        n = (netloc or "").lower()
        if not n:
            return False
        return n in in_scope_set

    try:
        with open(gau_in, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if not u:
                    continue
                # basic sanity
                if not (u.startswith("http://") or u.startswith("https://")):
                    continue

                p = urlparse(u)
                if host_ok(p.netloc):
                    inscope.append(u)
                else:
                    external.append(u)
    except Exception:
        pass

    # unique + stable order
    inscope = sorted(set(inscope))
    external = sorted(set(external))

    with open(gau_clean_out, "w", encoding="utf-8") as f:
        for u in inscope:
            f.write(u + "\n")

    if out_external_txt:
        with open(out_external_txt, "w", encoding="utf-8") as f:
            for u in external:
                f.write(u + "\n")

    return {
        "count": len(inscope),
        "external_count": len(external)
    }

# ---------------- Step 7.3 GoSpider parsing ----------------
def parse_gospider_raw_to_urls_txt(gospider_raw_txt: str, out_txt: str) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    if not os.path.exists(gospider_raw_txt):
        _write_lines(out_txt, [])
        return {"status": "missing", "gospider_in": gospider_raw_txt, "out_txt": out_txt, "count": 0}

    url_re = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

    urls: set[str] = set()
    with open(gospider_raw_txt, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for u in url_re.findall(line):
                # trim trailing punctuation that sometimes sticks
                u = u.rstrip(").,;\"'")
                urls.add(u)

    clean = sorted(urls)
    _write_lines(out_txt, clean)

    return {"status": "ok", "gospider_in": gospider_raw_txt, "out_txt": out_txt, "count": len(clean)}

#----- step 8.1 smb-----
def run_smbclient_list(ip: str, out_txt: str, timeout: int = 120) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)
    err_path = out_txt + ".err"

    # anonymous list
    cmd = ["smbclient", "-L", f"//{ip}", "-N"]

    rc = run_cmd(cmd, out_path=out_txt, err_path=err_path, timeout=timeout)

    return {
        "ip": ip,
        "rc": rc,
        "artifacts": {"out_txt": out_txt, "stderr": err_path},
        "status": "ok" if rc == 0 else "failed"
    }

def parse_nmap_xml_for_smb(nmap_xml_path: str, out_txt: str) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    if not os.path.exists(nmap_xml_path):
        _write_lines(out_txt, [])
        return {"status": "missing", "count": 0}

    try:
        tree = ET.parse(nmap_xml_path)
        root = tree.getroot()
    except Exception as e:
        _write_lines(out_txt, [])
        return {"status": "error", "error": str(e), "count": 0}

    smb_ports = []
    lines = []

    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"

        for port in host.findall(".//port"):
            portid = port.get("portid")
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            if portid not in ("139", "445"):
                continue

            service = port.find("service")
            service_name = service.get("name") if service is not None else ""
            product = service.get("product") if service is not None else ""
            version = service.get("version") if service is not None else ""
            extrainfo = service.get("extrainfo") if service is not None else ""

            entry = {
                "ip": ip,
                "port": int(portid),
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo
            }

            smb_ports.append(entry)

            lines.append(f"Host: {ip}")
            lines.append(f"Port: {portid}")
            lines.append(f"Service: {service_name}")
            lines.append(f"Product: {product}")
            lines.append(f"Version: {version}")
            lines.append(f"Extra: {extrainfo}")
            lines.append("-" * 40)

    _write_lines(out_txt, lines)

    return {
        "status": "ok",
        "count": len(smb_ports),
        "items": smb_ports,
        "out_txt": out_txt
    }
def run_smbclient_anonymous(
    ip: str,
    out_txt: str,
    timeout: int = 120
) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    err_path = out_txt + ".err"
    runner_path = out_txt + ".runner"

    cmd = ["smbclient", "-L", f"//{ip}", "-N"]

    rc = run_cmd(cmd, out_path=runner_path, err_path=err_path, timeout=timeout)

    try:
        if os.path.exists(runner_path):
            with open(runner_path, "r", encoding="utf-8", errors="replace") as fsrc:
                data = fsrc.read()
            with open(out_txt, "w", encoding="utf-8") as fdst:
                fdst.write(data)
            os.remove(runner_path)
        else:
            # Ensure file exists even if command produced nothing
            if not os.path.exists(out_txt):
                with open(out_txt, "w", encoding="utf-8") as f:
                    f.write("")
    except Exception:
        pass

    status = "ok"
    note = ""
    stderr = ""
    try:
        if os.path.exists(err_path):
            with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                stderr = f.read()
    except Exception:
        stderr = ""

    if rc != 0:
        status = "error"

    low = (stderr or "").lower()
    if "nt_status_access_denied" in low:
        note = "Access denied (anonymous not allowed)."
    elif "connection to" in low and "failed" in low:
        note = "Connection failed."
    elif "protocol negotiation failed" in low:
        note = "Protocol negotiation failed."
    elif "timed out" in low:
        note = "Timed out."

    return {
        "ip": ip,
        "rc": rc,
        "status": status,
        "note": note,
        "artifacts": {
            "stdout_txt": out_txt,
            "stderr": err_path
        }
    }

def write_smb_summary_txt(smb_result: dict, out_txt: str) -> dict:
    os.makedirs(os.path.dirname(out_txt), exist_ok=True)

    ip = smb_result.get("ip", "")
    status = smb_result.get("status", "unknown")
    rc = smb_result.get("rc", None)
    note = smb_result.get("note", "")

    stdout_path = smb_result.get("artifacts", {}).get("stdout_txt", "")
    stderr_path = smb_result.get("artifacts", {}).get("stderr", "")

    lines = []
    lines.append(f"SMB Anonymous Check (smbclient -L //{ip} -N)")
    lines.append(f"status: {status} | rc: {rc}")
    if note:
        lines.append(f"note: {note}")
    lines.append("")
    lines.append(f"stdout: {stdout_path}")
    lines.append(f"stderr: {stderr_path}")
    lines.append("")

    # include a short preview of stdout/stderr for terminal visibility
    def _preview(path: str, limit: int = 2000) -> str:
        try:
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(limit).rstrip()
        except Exception:
            pass
        return ""

    out_prev = _preview(stdout_path)
    err_prev = _preview(stderr_path)

    if out_prev:
        lines.append("---- stdout preview ----")
        lines.append(out_prev)
        lines.append("")
    if err_prev:
        lines.append("---- stderr preview ----")
        lines.append(err_prev)
        lines.append("")

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")

    return {"status": "ok", "out_txt": out_txt}