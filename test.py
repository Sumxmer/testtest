#!/usr/bin/env python3
"""
COSVINTE - Linux Capability Scanner
"Conquer Vulnerabilities"
"""

import os
import json
import stat
import pwd
import subprocess
import platform
from datetime import datetime
from fpdf import FPDF  # pip install fpdf2

# ==============================
# ANSI Colors
# ==============================
class Color:
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    RED       = "\033[91m"
    YELLOW    = "\033[93m"
    GREEN     = "\033[92m"
    CYAN      = "\033[96m"
    MAGENTA   = "\033[95m"
    WHITE     = "\033[97m"
    GRAY      = "\033[90m"
    ORANGE    = "\033[38;5;208m"
    BG_RED    = "\033[41m"
    BG_YELLOW = "\033[43m"

def c(color, text):
    return f"{color}{text}{Color.RESET}"

def severity_badge(sev):
    colors = {
        "CRITICAL": Color.BG_RED + Color.BOLD,
        "HIGH":     Color.RED + Color.BOLD,
        "MEDIUM":   Color.YELLOW + Color.BOLD,
        "LOW":      Color.GREEN,
    }
    return f"{colors.get(sev, Color.GRAY)} {sev} {Color.RESET}"

def cvss_bar(score, width=20):
    filled = int((score / 10.0) * width)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    if score >= 9:   color = Color.BG_RED + Color.BOLD
    elif score >= 7: color = Color.RED
    elif score >= 4: color = Color.YELLOW
    else:            color = Color.GREEN
    return f"{color}{bar}{Color.RESET} {Color.BOLD}{score:.1f}{Color.RESET}"

# ==============================
# Capability Risk Database
# ==============================
CAP_DB = {
    "cap_sys_admin": {
        "severity": "CRITICAL", "base_score": 9.5,
        "description": "Effectively equivalent to root. Allows mount, pivot_root, kernel module load, arbitrary namespace ops.",
        "exploit": "docker escape, kernel module injection, overlay mount abuse",
        "cves": ["CVE-2022-0492", "CVE-2022-25636", "CVE-2021-22555"],
        "remediation": "Remove cap_sys_admin. Use specific caps instead. Never assign to untrusted binaries."
    },
    "cap_setuid": {
        "severity": "CRITICAL", "base_score": 9.0,
        "description": "Allows setting arbitrary UID. Attacker can switch to UID 0 (root) at will.",
        "exploit": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "cves": ["CVE-2021-4034", "CVE-2019-14287"],
        "remediation": "Remove cap_setuid from all non-essential binaries. Audit with: getcap -r / 2>/dev/null"
    },
    "cap_setgid": {
        "severity": "HIGH", "base_score": 8.0,
        "description": "Allows setting arbitrary GID. Attacker can join privileged groups (shadow, disk, docker).",
        "exploit": "Switch to GID of shadow group to read /etc/shadow hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_setgid. Ensure binaries only have minimum required capabilities."
    },
    "cap_dac_override": {
        "severity": "HIGH", "base_score": 7.5,
        "description": "Bypasses all file read/write/execute permission checks. Can read /etc/shadow, /root/.",
        "exploit": "Read /etc/shadow, overwrite /etc/passwd, modify SUID binaries",
        "cves": ["CVE-2023-4911", "CVE-2016-1247"],
        "remediation": "Remove cap_dac_override. Use ACLs for specific file access instead."
    },
    "cap_dac_read_search": {
        "severity": "HIGH", "base_score": 7.0,
        "description": "Bypasses file read and directory search permission checks. Allows reading any file.",
        "exploit": "tar -czf /tmp/shadow.tar.gz /etc/shadow",
        "cves": ["CVE-2014-8990"],
        "remediation": "Remove cap_dac_read_search. Restrict to specific backup tools only."
    },
    "cap_net_admin": {
        "severity": "MEDIUM", "base_score": 6.5,
        "description": "Full network configuration access. Can modify routing, firewall rules, sniff traffic.",
        "exploit": "iptables -F (flush all firewall rules), ARP spoofing, traffic capture",
        "cves": ["CVE-2020-14386", "CVE-2016-8655"],
        "remediation": "Limit to network management daemons only. Never assign to scripting languages."
    },
    "cap_net_raw": {
        "severity": "MEDIUM", "base_score": 6.0,
        "description": "Allows raw socket creation. Enables network sniffing, spoofing, and ICMP manipulation.",
        "exploit": "tcpdump credential capture, ARP/ICMP spoofing, packet injection",
        "cves": ["CVE-2020-14386"],
        "remediation": "Limit cap_net_raw to specific tools (ping, tcpdump). Never assign broadly."
    },
    "cap_sys_ptrace": {
        "severity": "HIGH", "base_score": 8.5,
        "description": "Allows ptrace on any process. Can inject code into running processes including root-owned ones.",
        "exploit": "Inject shellcode into /sbin/init or any privileged process",
        "cves": ["CVE-2019-13272", "CVE-2021-3492"],
        "remediation": "Remove cap_sys_ptrace. Set sysctl kernel.yama.ptrace_scope=2."
    },
    "cap_sys_module": {
        "severity": "CRITICAL", "base_score": 9.8,
        "description": "Allows loading/unloading kernel modules. Complete kernel code execution as root.",
        "exploit": "insmod /tmp/rootkit.ko - full kernel rootkit installation",
        "cves": ["CVE-2019-2025"],
        "remediation": "Remove immediately. Lock kernel modules: sysctl kernel.modules_disabled=1"
    },
    "cap_chown": {
        "severity": "HIGH", "base_score": 7.8,
        "description": "Allows changing file ownership arbitrarily. Can take ownership of any file.",
        "exploit": "chown attacker /etc/shadow && read hashes",
        "cves": ["CVE-2021-4034"],
        "remediation": "Remove cap_chown from non-essential binaries. Audit carefully."
    },
    "cap_fowner": {
        "severity": "MEDIUM", "base_score": 6.5,
        "description": "Bypasses permission checks for operations requiring file ownership match.",
        "exploit": "chmod 777 /etc/shadow - make sensitive files world-readable",
        "cves": [],
        "remediation": "Remove cap_fowner. Use targeted file ACLs instead."
    },
    "cap_sys_rawio": {
        "severity": "CRITICAL", "base_score": 9.2,
        "description": "Raw I/O access to block devices. Can read/write raw disk including /dev/sda.",
        "exploit": "dd if=/dev/sda | grep -a password - extract credentials from raw disk",
        "cves": [],
        "remediation": "Remove immediately. Never assign to user-accessible binaries."
    },
    "cap_kill": {
        "severity": "LOW", "base_score": 3.5,
        "description": "Allows sending signals to any process. Can kill critical system daemons.",
        "exploit": "kill -9 1 (kill init/systemd) causing system crash",
        "cves": [],
        "remediation": "Restrict to specific process management tools only."
    },
    "cap_sys_chroot": {
        "severity": "MEDIUM", "base_score": 6.0,
        "description": "Allows chroot to arbitrary directories. Combined with other caps can escape sandbox.",
        "exploit": "chroot escape combined with cap_sys_admin or writable filesystem",
        "cves": ["CVE-2015-1318"],
        "remediation": "Remove cap_sys_chroot or combine with seccomp/AppArmor restrictions."
    },
    "cap_audit_write": {
        "severity": "LOW", "base_score": 3.0,
        "description": "Allows writing to kernel audit log. Can be used to obscure attack traces.",
        "exploit": "Inject false audit entries to cover tracks during an attack",
        "cves": [],
        "remediation": "Only assign to audit daemons. Monitor audit log integrity."
    },
}

# ==============================
# System Info Helpers
# ==============================
def get_distro():
    try:
        r = subprocess.run(["lsb_release", "-d"], capture_output=True, text=True)
        return r.stdout.replace("Description:", "").strip()
    except:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=")[1].strip().strip('"')
        except:
            return "Unknown"

def get_file_owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except:
        return "unknown"

def is_world_writable(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except:
        return False

def is_setuid(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except:
        return False

def get_file_type(path):
    try:
        mode = os.stat(path).st_mode
        if stat.S_ISREG(mode): return "binary"
        if stat.S_ISDIR(mode): return "directory"
        if stat.S_ISLNK(mode): return "symlink"
    except:
        pass
    return "unknown"

# ==============================
# Scanner Core
# ==============================
def get_capabilities():
    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=60
        )
        return [l for l in result.stdout.strip().split("\n") if l.strip()]
    except FileNotFoundError:
        print(c(Color.YELLOW, "  'getcap' not found. Install: apt install libcap2-bin"))
        return []
    except Exception as e:
        print(c(Color.RED, f"  getcap error: {e}"))
        return []

def parse_cap_line(line):
    if "=" not in line:
        return None, None, None
    parts     = line.split("=", 1)
    path      = parts[0].strip()
    cap_str   = parts[1].strip().lower()
    cap_types = []
    if "+e" in cap_str or "=ep" in cap_str or "eip" in cap_str:
        cap_types.append("effective")
    if "+p" in cap_str or "=p" in cap_str:
        cap_types.append("permitted")
    if "+i" in cap_str or "=i" in cap_str:
        cap_types.append("inheritable")
    return path, cap_str, cap_types if cap_types else ["permitted"]

def analyze_capabilities(lines):
    findings, seen = [], set()
    for line in lines:
        path, cap_str, cap_types = parse_cap_line(line)
        if not path:
            continue
        for cap_name, cap_info in CAP_DB.items():
            if cap_name not in cap_str:
                continue
            key = f"{path}:{cap_name}"
            if key in seen:
                continue
            seen.add(key)

            writable     = is_world_writable(path)
            suid         = is_setuid(path)
            owner        = get_file_owner(path)
            ftype        = get_file_type(path)
            score        = cap_info["base_score"]
            risk_factors = []

            if writable:
                score += 0.5
                risk_factors.append("world-writable (+0.5)")
            if suid:
                score += 0.3
                risk_factors.append("SUID bit set (+0.3)")
            if owner != "root":
                score += 0.2
                risk_factors.append(f"owned by non-root: {owner} (+0.2)")
            if "effective" in cap_types:
                risk_factors.append("effective capability (immediately usable)")

            score       = min(round(score, 1), 10.0)
            binary_name = os.path.basename(path).lower()
            is_interp   = any(x in binary_name for x in [
                "python", "perl", "ruby", "node", "php",
                "bash", "sh", "dash", "lua", "tcl",
            ])
            if is_interp:
                risk_factors.append("scripting interpreter - trivial exploitation")
                score = min(score + 0.5, 10.0)

            findings.append({
                "binary":         path,
                "binary_name":    binary_name,
                "capability":     cap_name,
                "cap_type":       ", ".join(cap_types),
                "severity":       cap_info["severity"],
                "risk_score":     score,
                "owner":          owner,
                "world_writable": writable,
                "suid":           suid,
                "file_type":      ftype,
                "is_interpreter": is_interp,
                "risk_factors":   risk_factors,
                "description":    cap_info["description"],
                "exploit_hint":   cap_info["exploit"],
                "cves":           cap_info["cves"],
                "remediation":    cap_info["remediation"],
            })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return findings

# ==============================
# Lab Simulation
# ==============================
def setup_lab():
    print(c(Color.CYAN, "\n  [*] Using Lab Simulation mode\n"))
    return [
        "/usr/bin/python3.11 = cap_setuid+ep",
        "/usr/bin/perl = cap_dac_override+ep",
        "/usr/bin/tcpdump = cap_net_raw+ep",
        "/usr/bin/ping = cap_net_raw+p",
        "/usr/sbin/dumpcap = cap_net_admin,cap_net_raw+ep",
        "/usr/bin/vim.basic = cap_dac_read_search+ep",
        "/usr/local/bin/custom_tool = cap_sys_admin+ep",
        "/usr/bin/node = cap_setuid,cap_setgid+ep",
    ]

# ==============================
# Terminal Output
# ==============================
def print_banner():
    print(f"""
{c(Color.CYAN+Color.BOLD, '''
 ██████╗ ██████╗ ███████╗██╗   ██╗██╗███╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗██╔════╝██║   ██║██║████╗  ██║╚══██╔══╝██╔════╝
██║     ██║   ██║███████╗██║   ██║██║██╔██╗ ██║   ██║   █████╗
██║     ██║   ██║╚════██║╚██╗ ██╔╝██║██║╚██╗██║   ██║   ██╔══╝
╚██████╗╚██████╔╝███████║ ╚████╔╝ ██║██║ ╚████║   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝''')}
{c(Color.GRAY, '         Linux Capability Scanner  |  "Conquer Vulnerabilities"')}
""")

def print_sysinfo(mode_label):
    print(c(Color.CYAN+Color.BOLD,
            "  ╔══ SYSTEM INFORMATION ══════════════════════════════════╗"))
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Hostname  :')} {c(Color.WHITE, platform.node())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Distro    :')} {c(Color.WHITE, get_distro())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Arch      :')} {c(Color.WHITE, platform.machine())}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Mode      :')} {c(Color.YELLOW, mode_label)}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Caps in DB:')} {c(Color.WHITE, str(len(CAP_DB)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Timestamp :')} "
          f"{c(Color.WHITE, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(c(Color.CYAN+Color.BOLD,
            "  ╚═════════════════════════════════════════════════════════╝\n"))

def print_findings(findings):
    if not findings:
        print(c(Color.GREEN+Color.BOLD, "\n  No dangerous capabilities found.\n"))
        return
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        groups.get(f["severity"], groups["LOW"]).append(f)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = groups[sev]
        if not group:
            continue
        sev_color = {
            "CRITICAL": Color.BG_RED+Color.BOLD,
            "HIGH":     Color.RED+Color.BOLD,
            "MEDIUM":   Color.YELLOW+Color.BOLD,
            "LOW":      Color.GREEN,
        }.get(sev, Color.GRAY)
        print(f"\n{sev_color}  -- {sev} ({len(group)}) --{Color.RESET}")
        for f in group:
            interp_icon = c(Color.RED+Color.BOLD, " [INTERPRETER]") if f["is_interpreter"] else ""
            ww_icon     = c(Color.ORANGE, " [WRITABLE]")            if f["world_writable"] else ""
            suid_icon   = c(Color.YELLOW, " [SUID]")                if f["suid"] else ""
            print(f"\n  {c(Color.RED+Color.BOLD,'[!]')}  "
                  f"{c(Color.WHITE+Color.BOLD, f['binary'])}"
                  f"{interp_icon}{ww_icon}{suid_icon}")
            print(f"     {c(Color.GRAY,'Capability :')} "
                  f"{c(Color.MAGENTA+Color.BOLD, f['capability'])}  "
                  f"{c(Color.GRAY,'type:')} {c(Color.CYAN, f['cap_type'])}")
            print(f"     {c(Color.GRAY,'Risk Score :')} {cvss_bar(f['risk_score'])}")
            print(f"     {c(Color.GRAY,'Description:')} "
                  f"{f['description'][:80]}{'...' if len(f['description'])>80 else ''}")
            if f["risk_factors"]:
                print(f"     {c(Color.ORANGE,'[!] Factors :')} "
                      f"{c(Color.YELLOW,' | '.join(f['risk_factors'][:3]))}")
            if f["exploit_hint"]:
                print(f"     {c(Color.RED,'[X] Exploit :')} "
                      f"{c(Color.GRAY, f['exploit_hint'][:75])}")
            if f["cves"]:
                print(f"     {c(Color.GRAY,'CVEs        :')} "
                      f"{'  '.join(c(Color.CYAN, cv) for cv in f['cves'][:3])}")
            print(f"     {c(Color.GREEN,'[+] Fix     :')} "
                  f"{c(Color.GRAY, f['remediation'][:80])}")

def print_summary(findings):
    critical  = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high      = sum(1 for f in findings if f["severity"] == "HIGH")
    medium    = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low       = sum(1 for f in findings if f["severity"] == "LOW")
    interps   = sum(1 for f in findings if f["is_interpreter"])
    ww        = sum(1 for f in findings if f["world_writable"])
    max_score = max((f["risk_score"] for f in findings), default=0)

    def sev(s):
        if s >= 9: return "CRITICAL"
        if s >= 7: return "HIGH"
        if s >= 4: return "MEDIUM"
        if s > 0:  return "LOW"
        return "NONE"

    print(f"\n{c(Color.CYAN+Color.BOLD, '  ╔══ SCAN SUMMARY ══════════════════════════════════════════╗')}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Total Binaries with Caps :')} "
          f"{c(Color.WHITE+Color.BOLD, str(len(findings)))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.BG_RED+Color.BOLD,'  CRITICAL               :')} "
          f"{c(Color.RED+Color.BOLD, str(critical))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.RED,'  HIGH                   :')} "
          f"{c(Color.RED+Color.BOLD, str(high))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.YELLOW,'  MEDIUM                 :')} "
          f"{c(Color.YELLOW+Color.BOLD, str(medium))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GREEN,'  LOW                    :')} "
          f"{c(Color.GREEN+Color.BOLD, str(low))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Scripting Interpreters   :')} "
          f"{c(Color.RED+Color.BOLD if interps else Color.GREEN, str(interps))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'World-Writable Binaries  :')} "
          f"{c(Color.RED+Color.BOLD if ww else Color.GREEN, str(ww))}")
    print(f"  {c(Color.CYAN,'║')}  {c(Color.GRAY,'Overall Risk Score       :')} "
          f"{severity_badge(sev(max_score))} {c(Color.BOLD, f'{max_score:.1f}')}")
    print(c(Color.CYAN+Color.BOLD,
            '  ╚═════════════════════════════════════════════════════════╝\n'))

# ==============================
# JSON Report
# ==============================
def save_json_report(findings):
    max_score = max((f["risk_score"] for f in findings), default=0)

    def sev(s):
        if s >= 9: return "CRITICAL"
        if s >= 7: return "HIGH"
        if s >= 4: return "MEDIUM"
        return "NONE"

    report = {
        "tool":      "COSVINTE - Linux Capability Scanner",
        "timestamp": datetime.now().isoformat(),
        "system": {
            "hostname": platform.node(),
            "distro":   get_distro(),
            "arch":     platform.machine(),
        },
        "summary": {
            "total_findings":   len(findings),
            "critical":         sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":             sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":           sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":              sum(1 for f in findings if f["severity"] == "LOW"),
            "overall_score":    max_score,
            "overall_severity": sev(max_score),
        },
        "findings": findings,
    }
    fname = f"cosvinte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as fh:
        json.dump(report, fh, indent=4)
    return fname

# ======================================================
# PDF REPORT ENGINE
# ======================================================
class CosvinteReport(FPDF):
    COLOR_DARK_BG   = (15,  20,  40)
    COLOR_ACCENT    = (0,   180, 220)
    COLOR_CRITICAL  = (210, 30,  30)
    COLOR_HIGH      = (210, 80,  20)
    COLOR_MEDIUM    = (190, 150, 0)
    COLOR_LOW       = (50,  160, 50)
    COLOR_TEXT      = (30,  30,  30)
    COLOR_SUBTEXT   = (100, 100, 120)
    COLOR_TABLE_HDR = (30,  40,  80)
    COLOR_ROW_ALT   = (242, 244, 250)

def __init__(self):
    super().__init__(orientation='P', unit='mm', format='A4')
    self.set_auto_page_break(auto=True, margin=20)

    # ชี้ไปยัง system font directory ที่ apt ติดตั้งให้
    # เป็นวิธีที่ดีกว่าการเก็บ font ไว้ข้างๆ script
    # เพราะ font จะถูก manage โดย OS และ update อัตโนมัติ
    font_dir = "/usr/share/fonts/truetype/dejavu"

    self.add_font("DejaVu",  style="",
                  fname=os.path.join(font_dir, "DejaVuSansCondensed.ttf"))
    self.add_font("DejaVu",  style="B",
                  fname=os.path.join(font_dir, "DejaVuSansCondensed-Bold.ttf"))
    self.add_font("DejaVu",  style="I",
                  fname=os.path.join(font_dir, "DejaVuSansCondensed-Oblique.ttf"))
    self.add_font("DejaVuM", style="",
                  fname=os.path.join(font_dir, "DejaVuSansMono.ttf"))
    self.add_font("DejaVuM", style="B",
                  fname=os.path.join(font_dir, "DejaVuSansMono-Bold.ttf"))


    def header(self):
        # หน้าแรกเป็น cover ไม่ต้องการ header bar
        if self.page_no() == 1:
            return
        self.set_fill_color(*self.COLOR_DARK_BG)
        self.rect(0, 0, 210, 14, style='F')
        self.set_font("DejaVu", style='B', size=8)
        self.set_text_color(*self.COLOR_ACCENT)
        self.set_xy(10, 4)
        self.cell(0, 6, "COSVINTE - Linux Capability Security Report", align='L')
        self.set_text_color(150, 150, 170)
        self.set_xy(0, 4)
        self.cell(200, 6, datetime.now().strftime("%Y-%m-%d"), align='R')
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.4)
        self.line(0, 14, 210, 14)
        self.ln(8)

    def footer(self):
        # หน้าแรกเป็น cover ไม่ต้องการ footer
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(1)
        self.set_font("DejaVu", style='I', size=7)
        self.set_text_color(150, 150, 150)
        self.set_x(10)
        self.cell(95, 5, "CONFIDENTIAL - For Authorized Personnel Only", align='L')
        self.cell(95, 5, f"Page {self.page_no()}", align='R')

    def severity_color(self, sev: str) -> tuple:
        return {
            "CRITICAL": self.COLOR_CRITICAL,
            "HIGH":     self.COLOR_HIGH,
            "MEDIUM":   self.COLOR_MEDIUM,
            "LOW":      self.COLOR_LOW,
        }.get(sev, (100, 100, 100))

    def draw_cvss_bar(self, x, y, score, bar_w=60):
        # filled_w คือสัดส่วน score/10 คูณความกว้าง bar เพื่อแสดงเป็น visual
        filled_w = (score / 10.0) * bar_w
        self.set_fill_color(220, 225, 235)
        self.rect(x, y, bar_w, 3.5, style='F')
        if score >= 9:   fc = self.COLOR_CRITICAL
        elif score >= 7: fc = self.COLOR_HIGH
        elif score >= 4: fc = self.COLOR_MEDIUM
        else:            fc = self.COLOR_LOW
        self.set_fill_color(*fc)
        self.rect(x, y, filled_w, 3.5, style='F')
        self.set_font("DejaVu", style='B', size=8)
        self.set_text_color(*fc)
        self.set_xy(x + bar_w + 2, y - 1)
        self.cell(14, 6, f"{score:.1f}/10", align='L')
        self.set_text_color(*self.COLOR_TEXT)

    def section_header(self, title: str, section_num: int = None):
        # accent bar สีฟ้า 2.5mm ด้านซ้ายบ่งบอก section ใหม่
        self.ln(4)
        bar_y = self.get_y()
        self.set_fill_color(*self.COLOR_ACCENT)
        self.rect(10, bar_y, 2.5, 9, style='F')
        prefix = f"{section_num:02d}. " if section_num else ""
        self.set_font("DejaVu", style='B', size=13)
        self.set_text_color(*self.COLOR_DARK_BG)
        self.set_xy(15, bar_y)
        self.cell(0, 9, f"{prefix}{title.upper()}", align='L')
        self.ln(2)
        self.set_draw_color(*self.COLOR_ACCENT)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)
        self.set_text_color(*self.COLOR_TEXT)

    def info_box(self, text: str, bg_color=(240, 244, 255),
                 text_color=None, border_color=None):
        # ความสูง box ประมาณจากจำนวนบรรทัดโดยนับทุก 88 ตัวอักษร = 1 บรรทัด
        if text_color   is None: text_color   = self.COLOR_TEXT
        if border_color is None: border_color = self.COLOR_ACCENT
        y     = self.get_y()
        lines = max(1, len(text) // 88 + text.count('\n') + 1)
        box_h = lines * 5 + 6
        self.set_fill_color(*bg_color)
        self.rect(10, y, 190, box_h, style='F')
        self.set_fill_color(*border_color)
        self.rect(10, y, 1.8, box_h, style='F')
        self.set_font("DejaVu", size=8.5)
        self.set_text_color(*text_color)
        self.set_xy(14, y + 3)
        self.multi_cell(183, 5, text)
        self.set_text_color(*self.COLOR_TEXT)
        self.ln(2)


# ==============================
# PDF Page Builders
# ==============================
def _overall_severity(score: float) -> str:
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    if score >  0: return "LOW"
    return "NONE"


def build_cover_page(pdf: CosvinteReport, findings: list, mode_label: str):
    pdf.add_page()

    # พื้นหลังสีเข้มครึ่งบนของหน้า
    pdf.set_fill_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.rect(0, 0, 210, 145, style='F')

    pdf.set_font("DejaVu", style='B', size=38)
    pdf.set_text_color(*CosvinteReport.COLOR_ACCENT)
    pdf.set_xy(0, 30)
    pdf.cell(210, 16, "COSVINTE", align='C')

    pdf.set_font("DejaVu", style='I', size=12)
    pdf.set_text_color(160, 175, 205)
    pdf.set_xy(0, 48)
    pdf.cell(210, 8, "Linux Capability Vulnerability Scanner", align='C')

    pdf.set_draw_color(*CosvinteReport.COLOR_ACCENT)
    pdf.set_line_width(0.8)
    pdf.line(55, 60, 155, 60)

    pdf.set_font("DejaVu", style='B', size=15)
    pdf.set_text_color(240, 240, 255)
    pdf.set_xy(0, 64)
    pdf.cell(210, 10, "SECURITY ASSESSMENT REPORT", align='C')

    # Overall Risk Badge ตรงกลางหน้า
    max_score = max((f["risk_score"] for f in findings), default=0)
    overall   = _overall_severity(max_score)
    color_map = {
        "CRITICAL": CosvinteReport.COLOR_CRITICAL,
        "HIGH":     CosvinteReport.COLOR_HIGH,
        "MEDIUM":   CosvinteReport.COLOR_MEDIUM,
        "LOW":      CosvinteReport.COLOR_LOW,
        "NONE":     (100, 100, 100),
    }
    pdf.set_fill_color(*color_map[overall])
    pdf.rect(70, 80, 70, 22, style='F')
    pdf.set_font("DejaVu", style='B', size=11)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(70, 82)
    pdf.cell(70, 8, f"OVERALL RISK: {overall}", align='C')
    pdf.set_font("DejaVu", size=9)
    pdf.set_xy(70, 90)
    pdf.cell(70, 8, f"Score: {max_score:.1f} / 10.0", align='C')

    # System Meta Table ครึ่งล่าง
    meta_items = [
        ("Target System",    platform.node()),
        ("Operating System", get_distro()),
        ("Architecture",     platform.machine()),
        ("Scan Mode",        mode_label),
        ("Report Date",      datetime.now().strftime("%B %d, %Y  %H:%M")),
        ("Generated By",     "COSVINTE v1.0  |  Capability Security Scanner"),
    ]
    start_y = 152
    for i, (label, value) in enumerate(meta_items):
        row_y = start_y + i * 12
        # สีสลับแถวเพื่อให้อ่านง่าย
        pdf.set_fill_color(*(245, 247, 253) if i % 2 == 0 else (255, 255, 255))
        pdf.rect(10, row_y, 190, 11, style='F')
        pdf.set_font("DejaVu", style='B', size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.set_xy(14, row_y + 2)
        pdf.cell(55, 6, label)
        pdf.set_font("DejaVu", size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.set_xy(70, row_y + 2)
        pdf.cell(128, 6, str(value))

    pdf.set_font("DejaVu", style='I', size=7)
    pdf.set_text_color(160, 160, 160)
    pdf.set_xy(10, 276)
    pdf.multi_cell(190, 4,
        "CONFIDENTIAL: This report contains sensitive security findings. "
        "Distribution is restricted to authorized personnel only. "
        "All findings should be remediated according to your organization security policy.",
        align='C')


def build_executive_summary(pdf: CosvinteReport, findings: list):
    pdf.add_page()
    pdf.section_header("Executive Summary", 1)

    critical  = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high      = sum(1 for f in findings if f["severity"] == "HIGH")
    medium    = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low       = sum(1 for f in findings if f["severity"] == "LOW")
    interps   = sum(1 for f in findings if f["is_interpreter"])
    max_score = max((f["risk_score"] for f in findings), default=0)
    overall   = _overall_severity(max_score)

    summary_text = (
        f"This security assessment identified {len(findings)} binaries on the target system "
        f"with potentially dangerous Linux capabilities assigned. Of these, {critical} are "
        f"rated CRITICAL, {high} HIGH, {medium} MEDIUM, and {low} LOW severity. "
        f"The overall risk score is {max_score:.1f}/10.0 ({overall}). "
        f"Immediate remediation is required for all CRITICAL and HIGH findings."
    )
    pdf.set_font("DejaVu", size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
    pdf.set_x(10)
    pdf.multi_cell(190, 6, summary_text)
    pdf.ln(4)

    # Stat Cards 4 กล่องเรียงแถว กว้างรวม 190mm
    card_configs = [
        ("CRITICAL", critical, CosvinteReport.COLOR_CRITICAL),
        ("HIGH",     high,     CosvinteReport.COLOR_HIGH),
        ("MEDIUM",   medium,   CosvinteReport.COLOR_MEDIUM),
        ("LOW",      low,      CosvinteReport.COLOR_LOW),
    ]
    card_y, card_w, card_h, gap = pdf.get_y(), 44, 28, 2.67

    for i, (label, count, color) in enumerate(card_configs):
        cx = 10 + i * (card_w + gap)
        pdf.set_fill_color(*color)
        pdf.rect(cx, card_y, card_w, card_h, style='F')
        pdf.set_font("DejaVu", style='B', size=22)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(cx, card_y + 3)
        pdf.cell(card_w, 12, str(count), align='C')
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_xy(cx, card_y + 15)
        pdf.cell(card_w, 7, label, align='C')
        pdf.set_font("DejaVu", size=7)
        pdf.set_xy(cx, card_y + 21)
        pdf.cell(card_w, 6, "findings", align='C')

    pdf.set_xy(10, card_y + card_h + 6)
    pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

    # Key Risk Highlights
    pdf.set_font("DejaVu", style='B', size=11)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 8, "Key Risk Highlights", align='L')
    pdf.ln(2)

    highlights = []
    if critical > 0:
        highlights.append(
            f"{critical} CRITICAL capability assignment(s) found. "
            f"These grant near-root privileges and must be removed immediately."
        )
    if interps > 0:
        highlights.append(
            f"{interps} scripting interpreter(s) (Python, Perl, Node, etc.) have dangerous "
            f"capabilities. Exploitable with a single one-liner command."
        )
    ww_count = sum(1 for f in findings if f["world_writable"])
    if ww_count > 0:
        highlights.append(
            f"{ww_count} world-writable binary(ies) with capabilities detected. "
            f"Any local user can replace the binary and escalate privileges."
        )
    highlights.append(
        "All CRITICAL and HIGH findings should be treated as active privilege escalation "
        "vectors until fully remediated and verified."
    )
    for h in highlights:
        pdf.info_box(h, bg_color=(255, 245, 245),
                     text_color=(100, 20, 20),
                     border_color=CosvinteReport.COLOR_CRITICAL)
        pdf.ln(1)

    # Top 5 Risk Table
    pdf.ln(3)
    pdf.set_font("DejaVu", style='B', size=11)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 8, "Top 5 Highest Risk Binaries", align='L')
    pdf.ln(2)

    headers    = ["Binary", "Capability", "Score", "Severity", "Interpreter?"]
    col_widths = [65, 50, 22, 28, 25]

    # หัวตาราง
    pdf.set_fill_color(*CosvinteReport.COLOR_TABLE_HDR)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("DejaVu", style='B', size=8.5)
    for h, w in zip(headers, col_widths):
        pdf.cell(w, 8, f"  {h}", border=0, fill=True, align='L')
    pdf.ln()

    # แถวข้อมูล top 5
    pdf.set_font("DejaVu", size=8.5)
    for i, f in enumerate(findings[:5]):
        pdf.set_fill_color(*(CosvinteReport.COLOR_ROW_ALT if i % 2 == 0 else (255, 255, 255)))
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        bin_name = f["binary"]
        if len(bin_name) > 32:
            bin_name = "..." + bin_name[-29:]
                # ต่อจาก pdf.cell(col_widths[0], 7, f"  {bin_name" ที่ค้างไว้
        pdf.cell(col_widths[0], 7, f"  {bin_name}", border=0, fill=True)
        pdf.cell(col_widths[1], 7, f"  {f['capability']}", border=0, fill=True)

        # เปลี่ยนสีตัวเลข score ตาม severity ของ finding นั้น
        sc = pdf.severity_color(f["severity"])
        pdf.set_text_color(*sc)
        pdf.cell(col_widths[2], 7, f"  {f['risk_score']:.1f}", border=0, fill=True)

        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(col_widths[3], 7, f"  {f['severity']}", border=0, fill=True)

        # แสดง YES หรือ No พร้อมเปลี่ยนสีให้ชัดเจน
        interp_txt = "YES (!)" if f["is_interpreter"] else "No"
        if f["is_interpreter"]:
            pdf.set_text_color(200, 30, 30)
        else:
            pdf.set_text_color(60, 130, 60)
        pdf.cell(col_widths[4], 7, f"  {interp_txt}", border=0, fill=True)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.ln()

    # เส้นปิดท้ายตาราง
    pdf.set_draw_color(200, 205, 220)
    pdf.set_line_width(0.2)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())


def build_detailed_findings(pdf: CosvinteReport, findings: list):
    """
    สร้างหน้า Detailed Findings โดยแต่ละ finding จะถูก render เป็น card
    ประกอบด้วย header bar สีเข้ม, CVSS bar, exploit box สีแดงอ่อน
    และ remediation box สีเขียวอ่อน เพื่อให้ผู้อ่านเห็นภาพรวมได้ทันที
    """
    pdf.add_page()
    pdf.section_header("Detailed Findings", 2)

    pdf.set_font("DejaVu", size=9)
    pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
    pdf.multi_cell(190, 5,
        "Each finding below represents a Linux capability assigned to a binary "
        "that poses a security risk. Findings are sorted by risk score (highest first). "
        "Exploit notes are provided for educational purposes to demonstrate real-world impact."
    )
    pdf.ln(3)

    for idx, f in enumerate(findings):

        # ตรวจสอบพื้นที่คงเหลือก่อนวาด card แต่ละอัน
        # ถ้าเหลือน้อยกว่า 210mm จากด้านบน ให้ขึ้นหน้าใหม่
        # เพื่อป้องกัน card ถูกตัดกลางระหว่างหน้า
        if pdf.get_y() > 210:
            pdf.add_page()

        card_top  = pdf.get_y()
        sev_color = pdf.severity_color(f["severity"])

        # ── Finding Header Bar ────────────────────────────────
        # วาด dark bar ความสูง 10mm สำหรับแสดงข้อมูลสำคัญในบรรทัดเดียว
        pdf.set_fill_color(*CosvinteReport.COLOR_DARK_BG)
        pdf.rect(10, card_top, 190, 10, style='F')

        # หมายเลข finding ด้านซ้ายสุด
        pdf.set_font("DejaVu", style='B', size=9)
        pdf.set_text_color(*CosvinteReport.COLOR_ACCENT)
        pdf.set_xy(13, card_top + 1.5)
        pdf.cell(12, 7, f"#{idx+1:02d}", align='L')

        # ชื่อ binary path ตัดให้พอดีถ้ายาวเกิน 55 ตัวอักษร
        bin_display = f["binary"]
        if len(bin_display) > 55:
            bin_display = "..." + bin_display[-52:]
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(25, card_top + 1.5)
        pdf.cell(130, 7, bin_display, align='L')

        # Severity badge ด้านขวาสุดของ header bar
        pdf.set_fill_color(*sev_color)
        pdf.rect(163, card_top + 1.5, 35, 7, style='F')
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(163, card_top + 2)
        pdf.cell(35, 6, f["severity"], align='C')

        # เลื่อน cursor มาใต้ header bar เพื่อเริ่มเขียนข้อมูล
        pdf.set_xy(10, card_top + 12)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)

        # ── Row 1: Capability / Type / Owner ─────────────────
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(28, 5, "Capability :")
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(80, 50, 160)
        pdf.cell(52, 5, f["capability"])

        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(18, 5, "Type :")
        pdf.set_font("DejaVu", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(42, 5, f["cap_type"])

        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(16, 5, "Owner :")
        pdf.set_font("DejaVu", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(30, 5, f["owner"])
        pdf.ln(6.5)

        # ── Row 2: CVSS Risk Score Bar ───────────────────────
        # draw_cvss_bar วาด progress bar ที่พิกัด x, y ที่ระบุ
        # x มาจากตำแหน่งหลังพิมพ์ label "Risk Score :"
        pdf.set_x(10)
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(28, 5, "Risk Score :")
        pdf.draw_cvss_bar(pdf.get_x(), pdf.get_y() + 0.8,
                          f["risk_score"], bar_w=75)
        pdf.ln(7)

        # ── Row 3: Description ───────────────────────────────
        pdf.set_x(10)
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(28, 5, "Description :")
        pdf.set_font("DejaVu", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        desc_x = pdf.get_x()
        pdf.set_xy(desc_x, pdf.get_y())
        pdf.multi_cell(190 - (desc_x - 10), 4.5, f["description"])
        pdf.ln(1)

        # ── Exploit Box (พื้นหลังแดงอ่อน) ───────────────────
        # ขอบซ้ายสีแดงเข้มเป็นสัญญาณอันตราย
        # ใช้ DejaVuM (Mono) สำหรับ command เพื่อให้ดูเหมือน terminal จริง
        if f["exploit_hint"]:
            ex_y = pdf.get_y()
            pdf.set_fill_color(255, 242, 242)
            pdf.rect(10, ex_y, 190, 13, style='F')
            pdf.set_fill_color(*CosvinteReport.COLOR_CRITICAL)
            pdf.rect(10, ex_y, 1.8, 13, style='F')

            pdf.set_font("DejaVu", style='B', size=8)
            pdf.set_text_color(180, 0, 0)
            pdf.set_xy(14, ex_y + 2)
            pdf.cell(35, 4, "Exploit Vector :")

            exploit_txt = f["exploit_hint"]
            if len(exploit_txt) > 90:
                exploit_txt = exploit_txt[:87] + "..."

            # DejaVuM คือ monospace font ทำให้ดูเหมือน terminal command จริง
            pdf.set_font("DejaVuM", size=7.5)
            pdf.set_text_color(120, 0, 0)
            pdf.set_xy(14, ex_y + 7)
            pdf.cell(184, 4, exploit_txt)
            pdf.set_xy(10, ex_y + 14)
            pdf.ln(1)

        # ── CVE Badges ───────────────────────────────────────
        # แต่ละ CVE วาดเป็น badge สีฟ้าอ่อน inline
        # ความกว้าง badge คำนวณจากความยาวข้อความ CVE number
        if f["cves"]:
            pdf.set_x(10)
            pdf.set_font("DejaVu", style='B', size=8)
            pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
            pdf.cell(28, 6, "Related CVEs :")
            for cve in f["cves"][:4]:
                cve_x   = pdf.get_x()
                cve_y   = pdf.get_y()
                badge_w = len(cve) * 2.1 + 5
                pdf.set_fill_color(220, 236, 255)
                pdf.rect(cve_x, cve_y, badge_w, 5.5, style='F')
                pdf.set_font("DejaVu", style='B', size=7.5)
                pdf.set_text_color(0, 60, 160)
                pdf.cell(badge_w, 5.5, cve, align='C')
                pdf.set_x(pdf.get_x() + 2)
            pdf.ln(7)

        # ── Risk Factors ─────────────────────────────────────
        if f["risk_factors"]:
            pdf.set_x(10)
            pdf.set_font("DejaVu", style='B', size=8)
            pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
            pdf.cell(28, 5, "Risk Factors :")
            pdf.set_font("DejaVu", size=8)
            pdf.set_text_color(160, 100, 0)
            pdf.set_x(38)
            pdf.multi_cell(160, 4.5, " | ".join(f["risk_factors"][:3]))
            pdf.ln(1)

        # ── Remediation Box (พื้นหลังเขียวอ่อน) ─────────────
        # ขอบซ้ายสีเขียวเป็นสัญญาณ "ทำสิ่งนี้เพื่อป้องกัน"
        # ความสูง box คำนวณจากความยาวข้อความ remediation
        rem_y     = pdf.get_y()
        rem_txt   = f["remediation"]
        rem_lines = max(1, len(rem_txt) // 88 + 1)
        rem_h     = rem_lines * 4.5 + 9

        pdf.set_fill_color(240, 255, 245)
        pdf.rect(10, rem_y, 190, rem_h, style='F')
        pdf.set_fill_color(50, 160, 80)
        pdf.rect(10, rem_y, 1.8, rem_h, style='F')

        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(30, 120, 50)
        pdf.set_xy(14, rem_y + 2)
        pdf.cell(35, 4, "Remediation :")

        pdf.set_font("DejaVu", size=8)
        pdf.set_text_color(20, 80, 35)
        pdf.set_xy(14, rem_y + 7)
        pdf.multi_cell(184, 4.5, rem_txt)

        # เส้นแบ่งระหว่าง card แต่ละอัน
        pdf.ln(4)
        pdf.set_draw_color(200, 210, 230)
        pdf.set_line_width(0.2)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)


def build_remediation_checklist(pdf: CosvinteReport, findings: list):
    """
    หน้า Remediation Checklist ออกแบบมาให้ Sysadmin ใช้งานจริง
    มี General Best Practices, per-finding checklist table
    และ Verification Commands ในรูปแบบ terminal dark box
    เพื่อให้ copy ไปใช้ได้ทันทีหลังจากแก้ไขแต่ละจุด
    """
    pdf.add_page()
    pdf.section_header("Remediation Checklist", 3)

    pdf.set_font("DejaVu", size=9)
    pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
    pdf.multi_cell(190, 5,
        "Use this checklist to track remediation progress. Items are ordered by severity. "
        "After each fix, verify with: getcap -r / 2>/dev/null "
        "and confirm the binary no longer appears in the output."
    )
    pdf.ln(4)

    # ── General Best Practices ────────────────────────────────
    pdf.set_font("DejaVu", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "General Best Practices", align='L')
    pdf.ln(2)

    best_practices = [
        "Audit all capabilities regularly with: getcap -r / 2>/dev/null",
        "Apply Principle of Least Privilege. Assign only the minimum capability required.",
        "Never assign capabilities to scripting interpreters (Python, Perl, Node, Bash, etc.)",
        "Use seccomp profiles and AppArmor/SELinux to further constrain capability usage.",
        "Monitor capability changes with auditd: auditctl -a always,exit -F arch=b64 -S capset",
        "Remove capabilities with setcap -r /path/to/binary instead of relying on file perms.",
        "Document all legitimate capability assignments with a clear business justification.",
    ]

    for bp in best_practices:
        row_y = pdf.get_y()
        pdf.set_fill_color(242, 246, 255)
        pdf.rect(10, row_y, 190, 7.5, style='F')
        # checkbox สี่เหลี่ยมเล็กๆ ด้านซ้าย ให้ Sysadmin ติ๊กเมื่อทำเสร็จ
        pdf.set_draw_color(160, 170, 200)
        pdf.set_line_width(0.3)
        pdf.rect(14, row_y + 1.8, 4, 4)
        pdf.set_font("DejaVu", size=8.5)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.set_xy(21, row_y + 1.5)
        pdf.cell(177, 5, bp)
        pdf.ln(8)

    pdf.ln(3)

    # ── Per-Finding Checklist Table ───────────────────────────
    pdf.set_font("DejaVu", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "Finding-Specific Remediation Tasks", align='L')
    pdf.ln(3)

    chk_headers = ["[ ]", "#", "Binary", "Capability", "Required Action", "Severity"]
    chk_widths  = [8, 8, 52, 33, 69, 20]

    # หัวตาราง
    pdf.set_fill_color(*CosvinteReport.COLOR_TABLE_HDR)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("DejaVu", style='B', size=8)
    for h, w in zip(chk_headers, chk_widths):
        pdf.cell(w, 8, f" {h}", border=0, fill=True)
    pdf.ln()

    # แถวข้อมูลแต่ละ finding พร้อม checkbox สำหรับติดตามงาน
    for i, f in enumerate(findings):
        if pdf.get_y() > 255:
            pdf.add_page()

        row_y = pdf.get_y()
        bg    = CosvinteReport.COLOR_ROW_ALT if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)

        # คอลัมน์ checkbox วาดกล่องสี่เหลี่ยมด้วย rect แทนการใช้ตัวอักษรพิเศษ
        pdf.cell(chk_widths[0], 7, "", border=0, fill=True)
        pdf.set_draw_color(160, 170, 200)
        pdf.set_line_width(0.25)
        pdf.rect(11.5, row_y + 1.5, 4, 4)

        # หมายเลข finding
        pdf.set_font("DejaVu", style='B', size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_SUBTEXT)
        pdf.cell(chk_widths[1], 7, f" {i+1:02d}", border=0, fill=True)

        # basename ของ binary ตัดให้พอดีคอลัมน์
        bin_short = os.path.basename(f["binary"])
        if len(bin_short) > 26:
            bin_short = bin_short[:23] + "..."
        pdf.set_font("DejaVu", size=8)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(chk_widths[2], 7, f" {bin_short}", border=0, fill=True)

        # capability name สีม่วงเพื่อให้โดดเด่น
        pdf.set_text_color(80, 50, 160)
        pdf.cell(chk_widths[3], 7, f" {f['capability']}", border=0, fill=True)

        # ใช้เฉพาะประโยคแรกของ remediation เพื่อให้พอดีคอลัมน์
        action = f["remediation"].split(".")[0]
        if len(action) > 40:
            action = action[:37] + "..."
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.cell(chk_widths[4], 7, f" {action}", border=0, fill=True)

        # severity ใช้สีตาม severity_color
        sc = pdf.severity_color(f["severity"])
        pdf.set_text_color(*sc)
        pdf.set_font("DejaVu", style='B', size=7.5)
        pdf.cell(chk_widths[5], 7, f" {f['severity']}", border=0, fill=True)
        pdf.set_text_color(*CosvinteReport.COLOR_TEXT)
        pdf.ln()

    # ── Verification Commands Section ────────────────────────
    pdf.ln(6)
    if pdf.get_y() > 220:
        pdf.add_page()

    pdf.set_font("DejaVu", style='B', size=10)
    pdf.set_text_color(*CosvinteReport.COLOR_DARK_BG)
    pdf.cell(0, 7, "Verification Commands", align='L')
    pdf.ln(3)

    # แสดงแต่ละ command เป็น dark terminal box
    # comment สีเทาอ่อนอยู่บรรทัดแรก ตาม command สีเขียวบรรทัดสอง
    verify_cmds = [
        ("List all capabilities system-wide",
         "getcap -r / 2>/dev/null"),
        ("Remove a specific capability from binary",
         "sudo setcap -r /path/to/binary"),
        ("Verify capability has been removed (expect empty output)",
         "getcap /path/to/binary"),
        ("Check process capabilities at runtime",
         "cat /proc/<PID>/status | grep -i cap"),
        ("Lock kernel module loading (CRITICAL hardening)",
         "sysctl -w kernel.modules_disabled=1"),
        ("Set ptrace scope to restrict process injection",
         "sysctl -w kernel.yama.ptrace_scope=2"),
    ]

    for desc, cmd in verify_cmds:
        if pdf.get_y() > 255:
            pdf.add_page()
        box_y = pdf.get_y()
        # dark background เลียนแบบ terminal จริง
        pdf.set_fill_color(*CosvinteReport.COLOR_DARK_BG)
        pdf.rect(10, box_y, 190, 14, style='F')
        # comment บรรทัดแรก สีเทาอ่อน
        pdf.set_font("DejaVu", size=7.5)
        pdf.set_text_color(160, 175, 210)
        pdf.set_xy(14, box_y + 2)
        pdf.cell(184, 4, f"# {desc}")
        # command บรรทัดสอง สีเขียว monospace
        pdf.set_font("DejaVuM", style='B', size=8.5)
        pdf.set_text_color(80, 220, 120)
        pdf.set_xy(14, box_y + 7)
        pdf.cell(184, 4, cmd)
        pdf.set_xy(10, box_y + 15)
        pdf.ln(1)

    # ── Footer Note ───────────────────────────────────────────
    pdf.ln(4)
    pdf.info_box(
        "After completing all remediations, perform a full re-scan with COSVINTE "
        "to verify that no dangerous capabilities remain. Schedule quarterly capability "
        "audits as part of your organization's security maintenance program.",
        bg_color=(235, 245, 255),
        text_color=(20, 60, 120),
        border_color=CosvinteReport.COLOR_ACCENT
    )


# ==============================
# Main PDF Generator Function
# ==============================
def save_pdf_report(findings: list, mode_label: str) -> str:
    """
    ฟังก์ชันหลักที่เรียก page builders ทั้ง 4 ตามลำดับแล้วบันทึกไฟล์
    โครงสร้าง PDF: Cover -> Executive Summary -> Detailed Findings -> Checklist
    ไฟล์จะถูกบันทึกในโฟลเดอร์ reports/ ข้างๆ ไฟล์ .py นี้เสมอ
    """
    pdf = CosvinteReport()

    print(c(Color.CYAN, "  [*] Building PDF report..."), end="", flush=True)

    build_cover_page(pdf, findings, mode_label)
    build_executive_summary(pdf, findings)
    build_detailed_findings(pdf, findings)
    build_remediation_checklist(pdf, findings)

    # ใช้ dirname + abspath เพื่อให้ได้ path ที่แน่นอนเสมอ
    # ไม่ว่าจะรันสคริปต์นี้จาก directory ไหนก็ตาม
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "reports")
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"cosvinte_report_{timestamp}.pdf"
    full_path = os.path.join(report_dir, filename)

    pdf.output(full_path)
    print(c(Color.GREEN, " done"))
    return full_path


# ==============================
# MAIN - Entry Point
# ==============================
def main():
    print_banner()

    print(c(Color.CYAN+Color.BOLD, "  Select Mode:"))
    print(f"  {c(Color.WHITE,'1')} {c(Color.GRAY,'-')} Real Scan  (getcap -r /)")
    print(f"  {c(Color.WHITE,'2')} {c(Color.GRAY,'-')} Lab Simulation (safe demo)\n")

    mode = input(c(Color.CYAN, "  Enter choice [1/2]: ")).strip()

    if mode == "2":
        lines      = setup_lab()
        mode_label = "Lab Simulation"
    else:
        mode_label = "Real Scan"
        print(c(Color.CYAN, "\n  [*] Running getcap -r / ..."), end="", flush=True)
        lines = get_capabilities()
        print(c(Color.GREEN, f" {len(lines)} entries found\n"))

    print_sysinfo(mode_label)

    # วิเคราะห์ capabilities ทั้งหมดที่พบจาก getcap หรือ lab simulation
    print(c(Color.CYAN, "  [*] Analyzing capabilities..."), end="", flush=True)
    findings = analyze_capabilities(lines)
    print(c(Color.GREEN, f" {len(findings)} findings\n"))

    # แสดงผลใน terminal ก่อน
    print_findings(findings)
    print_summary(findings)

    # บันทึก JSON report สำหรับการ parse ต่อด้วย tool อื่น
    json_path = save_json_report(findings)
    print(c(Color.GRAY, f"  JSON  saved -> {c(Color.WHITE+Color.BOLD, json_path)}"))

    # บันทึก PDF report สำหรับรายงานทางการ
    pdf_path = save_pdf_report(findings, mode_label)
    print(c(Color.GRAY, f"  PDF   saved -> {c(Color.WHITE+Color.BOLD, pdf_path)}\n"))


if __name__ == "__main__":
    main()
