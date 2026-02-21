import argparse
import os
import sys
import datetime
from urllib.parse import urlparse
import reconlib


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated Recon Tool (enumeration-only). Authorized targets only."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target (domain or IP)")
    group.add_argument("-f", "--file", help="File with targets (one per line)")

    parser.add_argument("-o", "--out", default="./run", help="Output directory (default: ./run)")
    parser.add_argument("-p", "--profile", choices=["fast", "deep"], default="fast", help="Scan profile")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Concurrency (default: 50)")
    parser.add_argument("-w", "--wordlist", default="wordlists/DirBuster-2007_directory-list-2.3-small.txt", help="Wordlist path for ffuf")
    parser.add_argument("--allow-private", dest="allow_private", action="store_true",
                        help="Allow private IP ranges (lab/VPN only)")

    return parser.parse_args()


def make_target_result(t: str) -> dict:
    return {
        "input": t,
        "type": None,
        "domain": None,
        "ip": None,
        "subdomains": [],
        "resolved_ips": [],
        "ports": {},      # ip -> [ports]
        "services": {},
        "modules": {},    # module_name -> {status, artifacts, data}
        "errors": [],
        "paths": {}       # store dirs here
    }


def main():
    args = parse_args()
    reconlib.print_banner()
    try:
        targets = reconlib.load_targets(args.target, args.file)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        return 1

    if not targets:
        print("[!] No valid targets provided.")
        return 1

    is_batch = args.file is not None and len(targets) > 1

    # Create run dirs depending on mode
    if is_batch:
        run_id, run_dir, targets_root = reconlib.make_batch_dirs(args.out, label="batch")
        raw_dir = None
    else:
        single = targets[0]
        run_id, run_dir, raw_dir = reconlib.make_single_target_dirs(args.out, single)
        targets_root = None

    # Run-level summary
    summary = {
        "run_id": run_id,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "profile": args.profile,
        "threads": args.threads,
        "wordlist": args.wordlist,
        "allow_private": args.allow_private,
        "mode": "batch" if is_batch else "single",
        "run_dir": run_dir,
        "targets": targets,
        "results": []
    }

    # Per-target setup + classification
    for t in targets:
        tr = make_target_result(t)

        # per-target directories
        if is_batch:
            target_dir, target_raw = reconlib.make_target_dirs_in_batch(targets_root, t)
            tr["paths"]["target_dir"] = target_dir
            tr["paths"]["raw_dir"] = target_raw
            tr["paths"]["target_summary_json"] = os.path.join(target_dir, "target_summary.json")
        else:
            tr["paths"]["target_dir"] = run_dir
            tr["paths"]["raw_dir"] = raw_dir
            tr["paths"]["target_summary_json"] = os.path.join(run_dir, "target_summary.json")

        # classify step2
        info = reconlib.classify_target(t)
        tr["type"] = info["type"]
        tr["domain"] = info.get("domain")
        tr["ip"] = info.get("ip")

        # print classification
        if tr["type"] == "domain":
            
            print(f"[+] Target DOMAIN: {tr['domain']}")
        elif tr["type"] == "ip":
            
            print(f"[+] Target IP:     {tr['ip']}")
        else:
            
            print(f"[!] Target INVALID: {tr['input']}")
            tr["errors"].append(f"Invalid target format: {info.get('reason', 'unknown')}")
            summary["results"].append(tr)
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
            continue

        # IP safety gate
        if tr["type"] == "ip":
            blocked, reason = reconlib.is_blocked_ip(tr["ip"], args.allow_private)
            if blocked:
                tr["errors"].append(f"Blocked IP: {reason}")
                summary["results"].append(tr)
                reconlib.write_json(tr["paths"]["target_summary_json"], tr)
                continue

        # (we do NOT run tools yet — Part 3 starts there)
        summary["results"].append(tr)
        reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        # --- STEP 3: Domain -> crt.sh -> resolve ---
        raw_dir = tr["paths"]["raw_dir"]

        for tool in ["crtsh", "curl", "ffuf", "gau", "gospider", "nikto", "nmap", "smb"]:
            reconlib.tool_dirs(raw_dir, tool)

        crt_raw_dir, crt_clean_dir = reconlib.tool_dirs(raw_dir, "crtsh")

        crt_raw = os.path.join(crt_raw_dir, "crtsh.json")
        subs_txt = os.path.join(crt_clean_dir, "subdomains.txt")
        resolved_txt = os.path.join(crt_clean_dir, "resolved.txt")
        resolve_json = os.path.join(crt_clean_dir, "resolve.json")

        if tr["type"] == "domain":
            domain = tr["domain"]

            # 1) crt.sh
            subs = reconlib.crtsh_enum(domain, crt_raw, subs_txt)
            tr["subdomains"] = subs

            tr["modules"]["crtsh"] = {
                "status": "ok",
                "artifacts": {
                    "raw_json": crt_raw,
                    "stderr": crt_raw + ".err",
                    "subdomains_txt": subs_txt
                },
                "counts": {"subdomains": len(subs)}
            }

            # 2) resolve (include the root domain too)
            to_resolve = list(dict.fromkeys(subs + [domain]))  # de-dup preserve order
            mapping, unique_ips = reconlib.resolve_hosts(to_resolve, resolved_txt, resolve_json)

            tr["resolved_ips"] = unique_ips
            tr["modules"]["resolve"] = {
                "status": "ok",
                "artifacts": {
                    "resolved_txt": resolved_txt,
                    "resolve_json": resolve_json
                },
                "counts": {
                    "hosts_attempted": len(to_resolve),
                    "hosts_resolved": sum(1 for h, ips in mapping.items() if ips),
                    "unique_ips": len(unique_ips)
                }
            }

            # write updated target summary immediately
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        #----- step 4 portscan & nmap -----
        scan_ips = []

        if tr["type"] == "ip":
            scan_ips = [tr["ip"]]
        elif tr["type"] == "domain":
            scan_ips = tr["resolved_ips"]

        if not scan_ips:
            tr["errors"].append("No IPs available to scan (no resolved IPs).")
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
            # continue to next target
            continue

        raw_dir = tr["paths"]["raw_dir"]

        for ip in scan_ips:
            ip_tag = ip.replace(".", "_")

            nmap_raw_dir, nmap_clean_dir = reconlib.tool_dirs(raw_dir, "nmap")

            portscan_path = os.path.join(nmap_raw_dir, f"portscan_{ip_tag}.txt")
            nmap_txt = os.path.join(nmap_raw_dir, f"nmap_{ip_tag}.txt")
            nmap_xml = os.path.join(nmap_raw_dir, f"nmap_{ip_tag}.xml")

            # 1) fast portscan
            open_ports, dt = reconlib.fast_portscan(
                ip=ip,
                ports=reconlib.COMMON_PORTS,
                threads=args.threads,
                timeout=0.3,
                out_path=portscan_path
            )

            tr["ports"][ip] = open_ports

            tr["modules"]["portscan"] = {
                "status": "ok",
                "artifacts": {
                    "portscan_txt": portscan_path
                },
                "counts": {
                    "ports_scanned": len(reconlib.COMMON_PORTS),
                    "open_ports": len(open_ports)
                },
                "metrics": {
                    "duration_seconds": round(dt, 3)
                }
            }

            # 2) targeted nmap
            rc = reconlib.targeted_nmap(
                ip=ip,
                open_ports=open_ports,
                out_txt=nmap_txt,
                out_xml=nmap_xml,
                timeout=600
            )

            tr["modules"]["nmap"] = {
                "status": "ok" if rc == 0 else "error",
                "artifacts": {
                    "nmap_txt": nmap_txt,
                    "nmap_xml": nmap_xml,
                    "stderr": nmap_txt + ".err"
                },
                "meta": {
                    "return_code": rc,
                    "ports_used": open_ports
                }
            }
        
        #------ step 5 service routing -----
        services = reconlib.build_services_from_ports(tr["ports"])
        tr["services"] = services
        tr["modules"]["routing"] = {
            "status": "ok",
            "counts": {"web":len(services["web"]), "smb": len(services["smb"])}
        }
        reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        #----- step 6.1 curl precheck-----
        web_targets = tr["services"].get("web", [])
        if not web_targets:
            tr["modules"]["curlcheck"] = {
                "status": "skipped",
                "reason": "no_web_targets",
                "counts": {"targets": 0}
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        else:
            raw_dir = tr["paths"]["raw_dir"]

            curl_results = []
            alive_urls = []

            for item in web_targets:
                url = item["url"]

                tag = reconlib.safe_tag_for_url(url)
                curl_raw_dir, curl_clean_dir = reconlib.tool_dirs(raw_dir, "curl")
                out_txt = os.path.join(curl_raw_dir, f"curl_{tag}.txt")

                result = reconlib.curl_precheck(url, out_txt, timeout=10)
                curl_results.append(result)

                if result["status_code"] is not None and result["status_code"] < 500:
                    alive_urls.append(url)

            # Save curl JSON results
            curl_json_path = os.path.join(curl_clean_dir, "curlcheck.json")
            reconlib.write_json(curl_json_path, curl_results)

            # Store alive list in services
            tr["services"]["web_alive"] = alive_urls

            tr["modules"]["curlcheck"] = {
                "status": "ok",
                "counts": {
                    "targets": len(web_targets),
                    "alive": len(alive_urls)
                },
                "artifacts": {
                    "curl_json": curl_json_path
                }
            }

            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        #----- step 6.2 nikto -----
        alive_urls = tr["services"].get("web_alive", [])
        if not alive_urls:
            tr["modules"]["nikto"] = {
                "status":"skipped",
                "reason":"no_web_alive",
                "counts":{"targets":0}
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        else: 
            raw_dir = tr["paths"]["raw_dir"]
            nikto_results = []
            
            for url in alive_urls:
                tag = reconlib.safe_tag_for_url(url)
                nikto_raw_dir, nikto_clean_dir = reconlib.tool_dirs(raw_dir, "nikto")

                out_txt = os.path.join(nikto_raw_dir, f"nikto_{tag}.txt")

                result = reconlib.run_nikto(url, out_txt, timeout=300)
                nikto_results.append(result)

            # Save nikto JSON results
            nikto_json_path = os.path.join(nikto_clean_dir, "nikto.json")
            reconlib.write_json(nikto_json_path, nikto_results)

            tr["modules"]["nikto"] = {
                "status": "ok",
                "counts": {
                    "targets": len(alive_urls)
                },
                "artifacts": {
                    "nikto_json": nikto_json_path
                }
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        #-------step 6.3 ffuf -------
        alive_urls = tr["services"].get("web_alive", [])
        if not alive_urls:
            tr["modules"]["ffuf"] = {
                "status": "skipped",
                "reason": "no_web_alive",
                "counts": {"targets": 0}
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        else:
            raw_dir = tr["paths"]["raw_dir"]
            ffuf_runs = []

            for base_url in alive_urls:
                tag = reconlib.safe_tag_for_url(base_url)
                ffuf_raw_dir, ffuf_clean_dir = reconlib.tool_dirs(raw_dir, "ffuf")
                out_json = os.path.join(ffuf_raw_dir, f"ffuf_{tag}.json")   

                res = reconlib.run_ffuf(
                    base_url=base_url,
                    wordlist=args.wordlist,
                    threads=args.threads,
                    out_json=out_json,
                    timeout=1200
                )
                ffuf_runs.append(res)

            ffuf_json_path = os.path.join(ffuf_clean_dir, "ffuf.json")
            reconlib.write_json(ffuf_json_path, ffuf_runs)

            tr["modules"]["ffuf"] = {
            "status": "ok",
            "counts": {"targets": len(alive_urls)},
            "items": ffuf_runs,
            "artifacts": {"ffuf_json": ffuf_json_path}
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        #----- step 6.4 gau -----
        raw_dir = tr["paths"]["raw_dir"]
        gau_raw_dir, gau_clean_dir = reconlib.tool_dirs(raw_dir, "gau")

        gau_txt = os.path.join(gau_raw_dir, "gau.txt")
        gau_dedup_txt = os.path.join(gau_clean_dir, "gau_dedup.txt")

        gau_res = reconlib.run_gau(tr["domain"], gau_txt, gau_dedup_txt, timeout=600)

        gau_json = os.path.join(gau_clean_dir, "gau.json")
        reconlib.write_json(gau_json, gau_res)

        tr["modules"]["gau"] = {
            "status": "ok" if gau_res.get("rc", 1) == 0 else "error",
            "artifacts": {
                "gau_json": gau_json,
                "gau_txt": gau_txt,
                "gau_dedup_txt": gau_dedup_txt,
                "stderr": gau_txt + ".err",
            },
            "counts": {
                "dedup_urls": gau_res.get("counts", {}).get("dedup_urls", 0)
            }
        }

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        #---- step 6.5 gospider ----
        alive_urls = tr["services"].get("web_alive", [])
        if not alive_urls:
            tr["modules"]["gospider"] = {
                "status": "skipped",
                "reason": "no_web_alive",
                "counts": {"targets": 0}
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        else:
            raw_dir = tr["paths"]["raw_dir"]
            spider_runs = []

            for base_url in alive_urls:
                tag = reconlib.safe_tag_for_url(base_url)
                gospider_raw_dir, gospider_clean_dir = reconlib.tool_dirs(raw_dir, "gospider")
                out_txt = os.path.join(gospider_raw_dir, f"gospider_{tag}.txt")

                res = reconlib.run_gospider(
                    url=base_url,
                    out_txt=out_txt,
                    threads=args.threads,
                    depth=2,
                    timeout=900
                )
                spider_runs.append(res)

            gospider_json_path = os.path.join(gospider_clean_dir, "gospider.json")
            reconlib.write_json(gospider_json_path, spider_runs)

            ok_count = sum(1 for r in spider_runs if r.get("rc") == 0)

            tr["modules"]["gospider"] = {
                "status": "ok" if ok_count == len(alive_urls) else "partial",
                "counts": {"targets": len(alive_urls), "ok": ok_count},
                "items": spider_runs,
                "artifacts": {"gospider_json": gospider_json_path}
            }

            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        print("FFUF keys:", tr.get("modules", {}).get("ffuf", {}).keys())
        print("GOSPIDER keys:", tr.get("modules", {}).get("gospider", {}).keys())
        print("FFUF items count:", len(tr.get("modules", {}).get("ffuf", {}).get("items", [])))
        print("GOSPIDER items count:", len(tr.get("modules", {}).get("gospider", {}).get("items", [])))
        print("RAW DIR:", tr["paths"]["raw_dir"])
        # ----- step 7 parsing -----
        raw_dir = tr["paths"]["raw_dir"]

        tr.setdefault("parsed", {})

        # 7.1 ffuf -> dirs txt (per ffuf run)
        if tr["modules"].get("ffuf", {}).get("status") == "ok":
            ffuf_dirs_txts = []
            for item in tr["modules"]["ffuf"].get("items", []):
                ffuf_json_path = item["artifacts"]["ffuf_json"]
                tag = reconlib.safe_tag_for_url(item["url"])
                ffuf_raw_dir, ffuf_clean_dir = reconlib.tool_dirs(raw_dir, "ffuf")
                out_txt = os.path.join(ffuf_clean_dir, f"ffuf_dirs_{tag}.txt")

                meta = reconlib.parse_ffuf_json_to_dirs_txt(ffuf_json_path, out_txt)
                ffuf_dirs_txts.append(meta)

            tr["parsed"]["ffuf"] = {
                "status": "ok",
                "items": ffuf_dirs_txts,
                "counts": {"total_dirs": sum(x.get("count", 0) for x in ffuf_dirs_txts)},
                "artifacts": {"dir_txts": [x["out_txt"] for x in ffuf_dirs_txts]},
            }
        else:
            tr["parsed"]["ffuf"] = {"status": "skipped", "reason": "ffuf_not_ok_or_not_run"}

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        # 7.2 gau -> cleaned urls txt (+ optional external split)
        gau_mod = tr["modules"].get("gau", {})
        if gau_mod.get("status") == "ok":
            artifacts = gau_mod.get("artifacts", {})
            gau_in = (artifacts.get("gau_dedup_txt")
                    or artifacts.get("gau_dedup")
                    or artifacts.get("gau_txt")
                    or artifacts.get("gau_out")
                    or os.path.join(raw_dir, "gau_dedup.txt"))

            gau_raw_dir, gau_clean_dir = reconlib.tool_dirs(raw_dir, "gau")
            gau_out = os.path.join(gau_clean_dir, "gau_clean.txt")
            gau_ext = os.path.join(gau_clean_dir, "gau_external.txt")

            allow_hosts = []
            if tr.get("domain"):
                allow_hosts.append(tr["domain"])
            for w in tr.get("services", {}).get("web_alive", []):
                allow_hosts.append(urlparse(w).netloc)

            meta = reconlib.parse_gau_to_txt(
                gau_in,
                gau_out,
                out_external_txt=gau_ext,
                in_scope_hosts=allow_hosts
            )

            tr["parsed"]["gau"] = {
                "status": "ok",
                "artifacts": {"gau_clean_txt": gau_out, "gau_external_txt": gau_ext},
                "counts": {
                    "in_scope": meta.get("count", 0),
                    "external": meta.get("external_count", 0),
                },
            }
        else:
            tr["parsed"]["gau"] = {"status": "skipped", "reason": "gau_not_ok_or_not_run"}

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        # 7.3 gospider -> urls txt (per gospider run)
        if tr["modules"].get("gospider", {}).get("status") == "ok":
            gospider_clean_txts = []
            for item in tr["modules"]["gospider"].get("items", []):
                raw_txt = item["artifacts"]["gospider_raw"]
                tag = reconlib.safe_tag_for_url(item["url"])
                gospider_raw_dir, gospider_clean_dir = reconlib.tool_dirs(raw_dir, "gospider")
                out_txt = os.path.join(gospider_clean_dir, f"gospider_urls_{tag}.txt")

                meta = reconlib.parse_gospider_raw_to_urls_txt(raw_txt, out_txt)
                gospider_clean_txts.append(meta)

            tr["parsed"]["gospider"] = {
                "status": "ok",
                "items": gospider_clean_txts,
                "counts": {"total_urls": sum(x.get("count", 0) for x in gospider_clean_txts)},
                "artifacts": {"url_txts": [x["out_txt"] for x in gospider_clean_txts]},
            }
        else:
            tr["parsed"]["gospider"] = {"status": "skipped", "reason": "gospider_not_ok_or_not_run"}

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        
        #------ step 8.1 smb -----
        smb_targets = tr.get("services", {}).get("smb", [])
        if not smb_targets:
            tr["modules"]["smb"] = {"status": "skipped", "reason": "no_smb_ports", "counts": {"targets": 0}}
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        else:
            raw_dir = tr["paths"]["raw_dir"]
            smb_items = []

            for s in smb_targets:
                ip = s["ip"]
                smb_raw_dir, smb_clean_dir = reconlib.tool_dirs(raw_dir, "smb")
                out_txt = os.path.join(smb_raw_dir, f"smbclient_{ip}.txt")
                smb_items.append(reconlib.run_smbclient_list(ip, out_txt, timeout=120))

            tr["modules"]["smb"] = {
                "status": "ok",
                "counts": {"targets": len(smb_items), "ok": sum(1 for x in smb_items if x["status"] == "ok")},
                "items": smb_items
            }
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)
        #smb nmap xml
        nmap_xml = tr["modules"]["nmap"]["artifacts"].get("nmap_xml")
        raw_dir = tr["paths"]["raw_dir"]
        smb_raw_dir, smb_clean_dir = reconlib.tool_dirs(raw_dir, "smb")
        smb_out_txt = os.path.join(smb_clean_dir, "smb_summary.txt")

        if nmap_xml and os.path.exists(nmap_xml):
            meta = reconlib.parse_nmap_xml_for_smb(nmap_xml, smb_out_txt)

            tr.setdefault("parsed", {})
            tr["parsed"]["smb"] = {
                "status": meta["status"],
                "counts": {"open_smb_ports": meta.get("count", 0)},
                "artifacts": {"smb_summary_txt": smb_out_txt}
            }
        else:
            tr.setdefault("parsed", {})
            tr["parsed"]["smb"] = {"status": "skipped"}

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)

        #---- smb reporting ----
        ip_for_smb = tr.get("ip")
        if not ip_for_smb:
            ips = tr.get("resolved_ips") or []
            ip_for_smb = ips[0] if ips else None

        open_ports_for_ip = []
        if ip_for_smb:
            open_ports_for_ip = (tr.get("ports", {}).get(ip_for_smb) or [])

        if ip_for_smb and 445 in open_ports_for_ip:
            smb_out = os.path.join(raw_dir, f"smbclient_{ip_for_smb}.txt")
            smb_res = reconlib.run_smbclient_anonymous(ip_for_smb, smb_out, timeout=120)

            smb_summary = os.path.join(smb_clean_dir, f"smb_summary_{ip_for_smb}.txt")
            reconlib.write_smb_summary_txt(smb_res, smb_summary)

            tr["modules"]["smb"] = {
                "status": "ok" if smb_res.get("status") == "ok" else "error",
                "ip": ip_for_smb,
                "result": smb_res,
                "artifacts": {
                    "smb_stdout_txt": smb_res["artifacts"]["stdout_txt"],
                    "smb_stderr": smb_res["artifacts"]["stderr"],
                    "smb_summary_txt": smb_summary
                }
            }
        else:
            tr["modules"]["smb"] = {
                "status": "skipped",
                "reason": "no_ip_or_445_not_open",
                "ip": ip_for_smb,
            }

        reconlib.write_json(tr["paths"]["target_summary_json"], tr)



        #------ step 9 reporting -----
        run_dir_safe = (
            tr.get("paths", {}).get("run_dir")
            or tr.get("paths", {}).get("run_directory")
            or tr.get("paths", {}).get("base_dir")
            or run_dir  # fallback to local variable if defined
        )

        report_md = os.path.join(run_dir_safe, "report.md")

        rep = reconlib.generate_report_md(tr, report_md)

        tr.setdefault("artifacts", {})
        tr["artifacts"]["report_md"] = report_md
        tr["artifacts"]["report_meta"] = rep

        reconlib.print_terminal_report(tr)

        if "paths" in tr and "target_summary_json" in tr["paths"]:
            reconlib.write_json(tr["paths"]["target_summary_json"], tr)

    # write updated target summary after each IP
    reconlib.write_json(tr["paths"]["target_summary_json"], tr)

    # Write top-level summary
    summary_path = os.path.join(run_dir, "summary.json")
    reconlib.write_json(summary_path, summary)

    print()
    print(f"[+] Run id:        {run_id}")
    print(f"[+] Mode:          {'BATCH' if is_batch else 'SINGLE'}")
    print(f"[+] Run directory: {run_dir}")
    if is_batch:
        print(f"[+] Targets root:  {targets_root}")
    else:
        print(f"[+] Raw directory: {raw_dir}")
    print(f"[+] Targets:       {len(targets)}")
    print(f"[+] Profile:       {args.profile}")
    print(f"[+] Threads:       {args.threads}")
    print(f"[+] Wordlist:      {args.wordlist}")
    print(f"[+] Allow private: {args.allow_private}")
    print(f"[+] Summary:       {summary_path}")
    print(f"[+] Report:        {os.path.join(run_dir, 'report.md')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
