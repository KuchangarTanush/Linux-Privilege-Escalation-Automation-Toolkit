#!/usr/bin/env python3
import os
import subprocess
import platform
import pwd

# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"

# -------------------------------
# Utility Functions
# -------------------------------
def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return ""

def print_section(title, emoji="🔎"):
    print("\n" + "="*60)
    print(f"{emoji} {BOLD}{title}{RESET}")
    print("="*60)

def severity_label(severity):
    if severity == "High":
        return f"{RED}🔴 HIGH{RESET}"
    elif severity == "Medium":
        return f"{YELLOW}🟠 MEDIUM{RESET}"
    else:
        return f"{GREEN}🟢 LOW{RESET}"

# -------------------------------
# System Information
# -------------------------------
def system_info():
    print_section("System Information", "💻")
    print(f"👤 User: {pwd.getpwuid(os.getuid()).pw_name}")
    print(f"👥 Groups: {os.getgroups()}")
    print(f"🖥️ Kernel: {platform.release()}")
    print(f"📀 OS: {platform.system()} {platform.version()}")

# -------------------------------
# SUID/SGID Binary Discovery
# -------------------------------
def suid_sgid_scan():
    print_section("SUID/SGID Binaries", "📂")
    suid_bins = run_command("find / -perm -4000 -type f 2>/dev/null")
    sgid_bins = run_command("find / -perm -2000 -type f 2>/dev/null")
    severity = "Low" if not suid_bins.strip() and not sgid_bins.strip() else "Medium"
    print("🔑 SUID Binaries:\n", suid_bins if suid_bins else "None found")
    print("🔑 SGID Binaries:\n", sgid_bins if sgid_bins else "None found")
    return ("SUID/SGID binaries", severity)

# -------------------------------
# Weak File & Directory Permissions
# -------------------------------
def weak_permissions_scan():
    print_section("Weak File & Directory Permissions", "📜")
    world_writable = run_command("find / -type f -perm -0002 2>/dev/null")
    passwd_perms = run_command("ls -l /etc/passwd").strip()
    shadow_perms = run_command("ls -l /etc/shadow").strip()

    severity = "Low"
    if world_writable.strip():
        severity = "Medium"

    print("🌍 World-writable files:\n", world_writable if world_writable else "None found")
    print(f"🔒 /etc/passwd permissions: {passwd_perms}")
    print(f"🔒 /etc/shadow permissions: {shadow_perms}")
    return ("Weak file permissions", severity)

# -------------------------------
# Misconfigured Services
# -------------------------------
def service_scan():
    print_section("Misconfigured Services", "⚙️")
    services = run_command("systemctl list-unit-files --type=service --state=enabled")
    sudo_rules = run_command("sudo -l")

    severity = "High" if "(ALL : ALL) ALL" in sudo_rules else "Low"

    print("🛠️ Enabled services:\n", services)
    print("🧩 Sudo configuration:\n", sudo_rules)
    return ("Sudo misconfiguration", severity)

# -------------------------------
# Cron Job Vulnerabilities
# -------------------------------
def cron_scan():
    print_section("Cron Jobs", "⏰")
    cron_root = run_command("cat /etc/crontab")
    cron_dirs = run_command("ls -la /etc/cron.*")

    severity = "Low"
    if "writable" in cron_dirs.lower():
        severity = "Medium"

    print("📋 System crontab:\n", cron_root)
    print("📂 Cron directories:\n", cron_dirs)
    return ("Cron jobs", severity)

# -------------------------------
# Kernel Exploit Detection
# -------------------------------
def kernel_vuln_scan():
    print_section("Kernel Vulnerability Check", "🐧")
    kernel_version = platform.release()
    severity = "Medium"  # Default: requires CVE lookup
    print(f"🖥️ Kernel version: {kernel_version}")
    print("⚠️ Check against CVE databases manually or via API integration.")
    return ("Kernel vulnerabilities", severity)

# -------------------------------
# Report Generation
# -------------------------------
def generate_report(findings):
    print_section("Final Security Report", "📊")
    print("📝 Findings categorized above with severity ratings:\n")
    overall = "Low"

    for item, severity in findings:
        print(f"- {item}: Severity = {severity_label(severity)}")
        if severity == "High":
            overall = "High"
        elif severity == "Medium" and overall != "High":
            overall = "Medium"

    print(f"\n🏁 Overall Risk Assessment: {severity_label(overall)}")
    print("\n✅ Suggested Mitigations:")
    print("   - Restrict permissions on sensitive files (/etc/passwd, /etc/shadow).")
    print("   - Remove or restrict risky SUID/SGID binaries.")
    print("   - Harden sudo rules (avoid ALL:ALL).")
    print("   - Secure cron jobs and service files.")
    print("   - Patch kernel to latest supported version.")

# -------------------------------
# Main Workflow
# -------------------------------
def main():
    system_info()
    findings = []
    findings.append(suid_sgid_scan())
    findings.append(weak_permissions_scan())
    findings.append(service_scan())
    findings.append(cron_scan())
    findings.append(kernel_vuln_scan())
    generate_report(findings)

if __name__ == "__main__":
    main()
