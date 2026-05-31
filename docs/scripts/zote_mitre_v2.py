#!/usr/bin/env python3
# zote_mitre_v2.py
# Run from ~/Desktop/ZOTE/
# Rewrites mitre.hpp and mitre_map.cpp with upgraded architecture

import pathlib

# ── mitre.hpp ─────────────────────────────────────────────────────────────
hpp = []
hpp.append("#pragma once")
hpp.append("// include/zote/mitre.hpp")
hpp.append("// ZOTE — zenithcpp Open Source Threat Engine")
hpp.append("// ISO C++23 compliant — zero external dependencies")
hpp.append("// Apache 2.0 License — https://github.com/zenithcpp/zote")
hpp.append("//")
hpp.append("// MITRE ATT&CK knowledge base.")
hpp.append("//")
hpp.append("// Coverage:")
hpp.append("//   Enterprise v14: 89+ techniques + sub-techniques")
hpp.append("//   ICS matrix:     87 techniques (T08xx)")
hpp.append("//   Threat actors:  APT28/29/41, Lazarus, LockBit,")
hpp.append("//                   FIN7, Cobalt, Sandworm, WizardSpider,")
hpp.append("//                   Kimsuky, MuddyWater")
hpp.append("//   Software:       Mimikatz, CobaltStrike, Metasploit,")
hpp.append("//                   Impacket, BloodHound, Sliver, Empire,")
hpp.append("//                   BruteRatel, Havoc, Meterpreter,")
hpp.append("//                   PsExec, Nmap")
hpp.append("//   Services:       ssh, rdp, smb, http/s, ftp, dns,")
hpp.append("//                   ldap, mssql, mysql, winrm, snmp,")
hpp.append("//                   nfs, vnc, telnet")
hpp.append("//   D3FEND:         countermeasure mappings")
hpp.append("//   Navigator:      ATT&CK Navigator 4.9 JSON export")
hpp.append("//")
hpp.append("// Thread-safety:")
hpp.append("//   All query functions are read-only and thread-safe.")
hpp.append("//   The database is compiled-in constexpr — no locking needed.")
hpp.append("//")
hpp.append("// v0.1 limitations (documented upgrade path):")
hpp.append("//   - Techniques use string keys internally (v1.0: interning)")
hpp.append("//   - Linear scan for lookups (v1.0: hash index)")
hpp.append("//   - Static functions only (v0.2: instantiable engine)")
hpp.append("//   - Mobile matrix returns empty (v0.2: full mobile)")
hpp.append("")
hpp.append("#include <zote/types.hpp>")
hpp.append("#include <functional>")
hpp.append("#include <string>")
hpp.append("#include <vector>")
hpp.append("")
hpp.append("namespace zote {")
hpp.append("")
hpp.append("// ─── MitreTechnique ──────────────────────────────────────────────────────")
hpp.append("// Represents a single ATT&CK technique or sub-technique.")
hpp.append("// All string fields are const char* (compiled-in data, no allocation).")
hpp.append("struct MitreTechnique {")
hpp.append("    const char* id;           // e.g. \"T1566\"")
hpp.append("    const char* sub_id;       // e.g. \"T1566.001\" (empty string if none)")
hpp.append("    const char* name;         // e.g. \"Phishing\"")
hpp.append("    const char* tactic;       // Primary tactic ID e.g. \"TA0001\"")
hpp.append("    const char* tactic_name;  // e.g. \"Initial Access\"")
hpp.append("    const char* description;  // Brief description")
hpp.append("    const char* platform;     // e.g. \"Linux,Windows,macOS\"")
hpp.append("    Severity    severity;     // Default severity for this technique")
hpp.append("};")
hpp.append("")
hpp.append("// ─── MitreDb ─────────────────────────────────────────────────────────────")
hpp.append("// Static knowledge base — no instantiation required.")
hpp.append("// All functions are stateless and thread-safe.")
hpp.append("//")
hpp.append("// Query API (composable):")
hpp.append("//   Use query(MitreQuery{}) to combine filters.")
hpp.append("//   Convenience functions (by_actor, by_service, etc.) wrap query().")
hpp.append("//")
hpp.append("// Return type:")
hpp.append("//   std::vector<TechniqueRef> — safe references into compiled-in DB.")
hpp.append("//   References are valid for the lifetime of the process.")
hpp.append("//   Raw const MitreTechnique* also available via lookup().")
hpp.append("class MitreDb {")
hpp.append("public:")
hpp.append("    // ── Direct lookup ─────────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Look up technique by ID or sub-technique ID.")
hpp.append("    // Returns nullptr if not found.")
hpp.append("    // e.g. lookup(\"T1566\") or lookup(\"T1566.001\")")
hpp.append("    [[nodiscard]] static const MitreTechnique*")
hpp.append("    lookup(const std::string& id) noexcept;")
hpp.append("")
hpp.append("    // Look up by TechniqueId strong type.")
hpp.append("    [[nodiscard]] static const MitreTechnique*")
hpp.append("    lookup(const TechniqueId& id) noexcept;")
hpp.append("")
hpp.append("    // ── Composable query ──────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Query with optional filters — any combination.")
hpp.append("    // All non-empty filters must match (AND semantics).")
hpp.append("    // Returns TechniqueRef vector — safe references into compiled-in DB.")
hpp.append("    [[nodiscard]] static std::vector<TechniqueRef>")
hpp.append("    query(const MitreQuery& q) noexcept;")
hpp.append("")
hpp.append("    // ── Convenience queries (wrap query()) ────────────────────────────")
hpp.append("")
hpp.append("    // All techniques for a tactic ID (e.g. \"TA0001\").")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    by_tactic(const std::string& tactic_id) noexcept;")
hpp.append("")
hpp.append("    // Techniques used by a known threat actor.")
hpp.append("    // Case-insensitive. e.g. \"APT28\", \"apt28\", \"Apt28\"")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    by_actor(const std::string& actor) noexcept;")
hpp.append("")
hpp.append("    // Techniques used by a software/tool.")
hpp.append("    // Case-insensitive. e.g. \"Mimikatz\", \"CobaltStrike\"")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    by_software(const std::string& software) noexcept;")
hpp.append("")
hpp.append("    // Techniques relevant to a service/port.")
hpp.append("    // Case-insensitive. e.g. \"ssh\", \"rdp\", \"smb\"")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    by_service(const std::string& service) noexcept;")
hpp.append("")
hpp.append("    // ── D3FEND countermeasures ────────────────────────────────────────")
hpp.append("")
hpp.append("    // Defensive countermeasures for a technique ID.")
hpp.append("    // Returns empty vector if technique has no D3FEND mapping.")
hpp.append("    [[nodiscard]] static std::vector<std::string>")
hpp.append("    d3fend_for(const std::string& technique_id) noexcept;")
hpp.append("")
hpp.append("    // ── ATT&CK Navigator export ───────────────────────────────────────")
hpp.append("")
hpp.append("    // Build a NavigatorLayer from technique IDs.")
hpp.append("    // Call layer.to_json() for JSON string output.")
hpp.append("    [[nodiscard]] static NavigatorLayer")
hpp.append("    build_layer(")
hpp.append("        const std::vector<std::string>& technique_ids,")
hpp.append("        const std::string&              layer_name,")
hpp.append("        const std::string&              color = \"#ff6666\") noexcept;")
hpp.append("")
hpp.append("    // Convenience: build layer and return JSON string directly.")
hpp.append("    [[nodiscard]] static std::string")
hpp.append("    navigator_export(")
hpp.append("        const std::vector<std::string>& technique_ids,")
hpp.append("        const std::string&              layer_name) noexcept;")
hpp.append("")
hpp.append("    // ── Matrix queries ────────────────────────────────────────────────")
hpp.append("")
hpp.append("    // All ICS matrix techniques (T08xx range).")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    ics_techniques() noexcept;")
hpp.append("")
hpp.append("    // Mobile matrix techniques.")
hpp.append("    // Note: returns empty in v0.1 — full mobile matrix in v0.2.")
hpp.append("    [[nodiscard]] static std::vector<const MitreTechnique*>")
hpp.append("    mobile_techniques() noexcept;")
hpp.append("")
hpp.append("    // ── Database metadata ─────────────────────────────────────────────")
hpp.append("")
hpp.append("    // Enterprise technique count.")
hpp.append("    [[nodiscard]] static std::size_t enterprise_size() noexcept;")
hpp.append("")
hpp.append("    // Total database size (Enterprise + ICS).")
hpp.append("    [[nodiscard]] static std::size_t total_size() noexcept;")
hpp.append("")
hpp.append("    // ATT&CK version string.")
hpp.append("    [[nodiscard]] static const char* attack_version() noexcept;")
hpp.append("};")
hpp.append("")
hpp.append("} // namespace zote")
hpp.append("")

pathlib.Path("include/zote/mitre.hpp").write_text(
    "\n".join(hpp), encoding="utf-8")
print(f"OK -- include/zote/mitre.hpp written ({len(hpp)} lines)")

# ── mitre_map.cpp ─────────────────────────────────────────────────────────
cpp = []
cpp.append("// src/mitre_map.cpp")
cpp.append("// ZOTE — zenithcpp Open Source Threat Engine")
cpp.append("// ISO C++23 compliant — zero external dependencies")
cpp.append("// Apache 2.0 License — https://github.com/zenithcpp/zote")
cpp.append("")
cpp.append("#include <zote/mitre.hpp>")
cpp.append("#include <algorithm>")
cpp.append("#include <sstream>")
cpp.append("#include <string>")
cpp.append("#include <vector>")
cpp.append("")
cpp.append("namespace zote {")
cpp.append("")
cpp.append("// ─── Enterprise technique database ───────────────────────────────────────")
cpp.append("static constexpr MitreTechnique ENTERPRISE_DB[] = {")

techniques = [
    ("T1566","","Phishing","TA0001","Initial Access","Adversaries send phishing emails to gain access","Linux,Windows,macOS",3),
    ("T1566","T1566.001","Spearphishing Attachment","TA0001","Initial Access","Malicious file attachment in targeted email","Linux,Windows,macOS",4),
    ("T1566","T1566.002","Spearphishing Link","TA0001","Initial Access","Malicious link in targeted email","Linux,Windows,macOS",3),
    ("T1190","","Exploit Public-Facing Application","TA0001","Initial Access","Exploit weakness in internet-facing system","Linux,Windows,macOS",4),
    ("T1189","","Drive-by Compromise","TA0001","Initial Access","Exploit browser visiting malicious website","Linux,Windows,macOS",3),
    ("T1199","","Trusted Relationship","TA0001","Initial Access","Compromise via third-party trusted access","Linux,Windows,macOS",3),
    ("T1195","","Supply Chain Compromise","TA0001","Initial Access","Compromise software supply chain","Linux,Windows,macOS",4),
    ("T1078","","Valid Accounts","TA0001","Initial Access","Use legitimate credentials for access","Linux,Windows,macOS",3),
    ("T1133","","External Remote Services","TA0001","Initial Access","Leverage VPN RDP or other remote services","Linux,Windows",3),
    ("T1059","","Command and Scripting Interpreter","TA0002","Execution","Abuse command-line interfaces","Linux,Windows,macOS",3),
    ("T1059","T1059.001","PowerShell","TA0002","Execution","Execute commands via PowerShell","Windows",3),
    ("T1059","T1059.003","Windows Command Shell","TA0002","Execution","Execute via cmd.exe","Windows",2),
    ("T1059","T1059.004","Unix Shell","TA0002","Execution","Execute via bash sh zsh","Linux,macOS",2),
    ("T1059","T1059.006","Python","TA0002","Execution","Execute via Python interpreter","Linux,Windows,macOS",2),
    ("T1053","","Scheduled Task/Job","TA0002","Execution","Abuse task scheduler for execution","Linux,Windows",3),
    ("T1053","T1053.005","Scheduled Task","TA0002","Execution","Windows Task Scheduler abuse","Windows",3),
    ("T1053","T1053.003","Cron","TA0002","Execution","Linux cron job abuse","Linux,macOS",3),
    ("T1106","","Native API","TA0002","Execution","Use OS native APIs directly","Linux,Windows,macOS",3),
    ("T1204","","User Execution","TA0002","Execution","Trick user into executing malicious content","Linux,Windows,macOS",3),
    ("T1547","","Boot/Logon Autostart Execution","TA0003","Persistence","Configure at boot/logon execution","Linux,Windows,macOS",3),
    ("T1547","T1547.001","Registry Run Keys","TA0003","Persistence","HKCU/HKLM run key persistence","Windows",3),
    ("T1543","","Create or Modify System Process","TA0003","Persistence","Create malicious service or daemon","Linux,Windows,macOS",3),
    ("T1543","T1543.003","Windows Service","TA0003","Persistence","Create or modify Windows service","Windows",3),
    ("T1546","","Event Triggered Execution","TA0003","Persistence","Execute via system events","Linux,Windows,macOS",3),
    ("T1136","","Create Account","TA0003","Persistence","Create local or domain account","Linux,Windows,macOS",3),
    ("T1505","","Server Software Component","TA0003","Persistence","Install malicious web shell or plugin","Linux,Windows,macOS",4),
    ("T1505","T1505.003","Web Shell","TA0003","Persistence","Deploy web shell for persistent access","Linux,Windows,macOS",4),
    ("T1068","","Exploitation for Privilege Escalation","TA0004","Privilege Escalation","Exploit vulnerability to gain higher privileges","Linux,Windows,macOS",4),
    ("T1055","","Process Injection","TA0004","Privilege Escalation","Inject code into another process","Linux,Windows,macOS",4),
    ("T1055","T1055.001","Dynamic-link Library Injection","TA0004","Privilege Escalation","Inject DLL into process","Windows",4),
    ("T1548","","Abuse Elevation Control Mechanism","TA0004","Privilege Escalation","Bypass UAC or sudo restrictions","Linux,Windows,macOS",3),
    ("T1548","T1548.003","Sudo and Sudo Caching","TA0004","Privilege Escalation","Abuse sudo for privilege escalation","Linux,macOS",3),
    ("T1134","","Access Token Manipulation","TA0004","Privilege Escalation","Steal or forge access tokens","Windows",4),
    ("T1070","","Indicator Removal","TA0005","Defense Evasion","Remove indicators to avoid detection","Linux,Windows,macOS",3),
    ("T1070","T1070.004","File Deletion","TA0005","Defense Evasion","Delete files to remove evidence","Linux,Windows,macOS",2),
    ("T1036","","Masquerading","TA0005","Defense Evasion","Disguise malicious activity as legitimate","Linux,Windows,macOS",3),
    ("T1027","","Obfuscated Files or Information","TA0005","Defense Evasion","Obfuscate content to evade detection","Linux,Windows,macOS",3),
    ("T1562","","Impair Defenses","TA0005","Defense Evasion","Disable security tools","Linux,Windows,macOS",4),
    ("T1562","T1562.001","Disable or Modify Tools","TA0005","Defense Evasion","Disable AV SIEM or EDR","Linux,Windows,macOS",4),
    ("T1112","","Modify Registry","TA0005","Defense Evasion","Modify registry to hide or persist","Windows",3),
    ("T1003","","OS Credential Dumping","TA0006","Credential Access","Dump OS credentials from memory or files","Linux,Windows,macOS",4),
    ("T1003","T1003.001","LSASS Memory","TA0006","Credential Access","Dump credentials from LSASS","Windows",4),
    ("T1003","T1003.008","/etc/passwd and /etc/shadow","TA0006","Credential Access","Read Linux password files","Linux",4),
    ("T1110","","Brute Force","TA0006","Credential Access","Guess or crack credentials","Linux,Windows,macOS",3),
    ("T1110","T1110.003","Password Spraying","TA0006","Credential Access","Try common passwords across many accounts","Linux,Windows,macOS",3),
    ("T1558","","Steal or Forge Kerberos Tickets","TA0006","Credential Access","Steal or create Kerberos tickets","Windows",4),
    ("T1558","T1558.003","Kerberoasting","TA0006","Credential Access","Request Kerberos TGS for offline cracking","Windows",4),
    ("T1555","","Credentials from Password Stores","TA0006","Credential Access","Extract credentials from password stores","Linux,Windows,macOS",3),
    ("T1082","","System Information Discovery","TA0007","Discovery","Enumerate system info OS version hardware","Linux,Windows,macOS",2),
    ("T1083","","File and Directory Discovery","TA0007","Discovery","Enumerate files and directories","Linux,Windows,macOS",2),
    ("T1057","","Process Discovery","TA0007","Discovery","Enumerate running processes","Linux,Windows,macOS",2),
    ("T1049","","System Network Connections Discovery","TA0007","Discovery","Enumerate active network connections","Linux,Windows,macOS",2),
    ("T1087","","Account Discovery","TA0007","Discovery","Enumerate local or domain accounts","Linux,Windows,macOS",2),
    ("T1046","","Network Service Discovery","TA0007","Discovery","Scan network for open ports and services","Linux,Windows,macOS",3),
    ("T1018","","Remote System Discovery","TA0007","Discovery","Enumerate remote systems on network","Linux,Windows,macOS",2),
    ("T1069","","Permission Groups Discovery","TA0007","Discovery","Enumerate group memberships","Linux,Windows,macOS",2),
    ("T1021","","Remote Services","TA0008","Lateral Movement","Use remote services for lateral movement","Linux,Windows,macOS",3),
    ("T1021","T1021.001","Remote Desktop Protocol","TA0008","Lateral Movement","RDP lateral movement","Windows",3),
    ("T1021","T1021.002","SMB/Windows Admin Shares","TA0008","Lateral Movement","SMB lateral movement","Windows",4),
    ("T1021","T1021.004","SSH","TA0008","Lateral Movement","SSH lateral movement","Linux,macOS",3),
    ("T1550","","Use Alternate Authentication Material","TA0008","Lateral Movement","Pass-the-hash pass-the-ticket","Windows",4),
    ("T1550","T1550.002","Pass the Hash","TA0008","Lateral Movement","Authenticate using NTLM hash","Windows",4),
    ("T1550","T1550.003","Pass the Ticket","TA0008","Lateral Movement","Authenticate using Kerberos ticket","Windows",4),
    ("T1534","","Internal Spearphishing","TA0008","Lateral Movement","Phish internally after initial access","Linux,Windows,macOS",3),
    ("T1560","","Archive Collected Data","TA0009","Collection","Archive data before exfiltration","Linux,Windows,macOS",3),
    ("T1074","","Data Staged","TA0009","Collection","Stage data for exfiltration","Linux,Windows,macOS",3),
    ("T1056","","Input Capture","TA0009","Collection","Capture keystrokes or credentials","Linux,Windows,macOS",3),
    ("T1113","","Screen Capture","TA0009","Collection","Capture screen contents","Linux,Windows,macOS",2),
    ("T1071","","Application Layer Protocol","TA0011","Command and Control","Use app layer protocols for C2","Linux,Windows,macOS",3),
    ("T1071","T1071.001","Web Protocols","TA0011","Command and Control","HTTP/HTTPS C2 traffic","Linux,Windows,macOS",3),
    ("T1071","T1071.004","DNS","TA0011","Command and Control","DNS tunneling for C2","Linux,Windows,macOS",4),
    ("T1573","","Encrypted Channel","TA0011","Command and Control","Encrypt C2 communications","Linux,Windows,macOS",3),
    ("T1573","T1573.002","Asymmetric Cryptography","TA0011","Command and Control","TLS/SSL encrypted C2","Linux,Windows,macOS",3),
    ("T1572","","Protocol Tunneling","TA0011","Command and Control","Tunnel C2 over legitimate protocol","Linux,Windows,macOS",4),
    ("T1219","","Remote Access Software","TA0011","Command and Control","Use commercial RAT for C2","Linux,Windows,macOS",3),
    ("T1090","","Proxy","TA0011","Command and Control","Route C2 through proxy","Linux,Windows,macOS",3),
    ("T1095","","Non-Application Layer Protocol","TA0011","Command and Control","Raw protocol C2 ICMP raw TCP","Linux,Windows,macOS",4),
    ("T1105","","Ingress Tool Transfer","TA0011","Command and Control","Transfer tools to compromised system","Linux,Windows,macOS",3),
    ("T1041","","Exfiltration Over C2 Channel","TA0010","Exfiltration","Exfiltrate data over existing C2","Linux,Windows,macOS",3),
    ("T1048","","Exfiltration Over Alternative Protocol","TA0010","Exfiltration","Exfiltrate via DNS FTP SMTP","Linux,Windows,macOS",4),
    ("T1048","T1048.003","Exfiltration Over Unencrypted Protocol","TA0010","Exfiltration","Exfiltrate via unencrypted channel","Linux,Windows,macOS",3),
    ("T1567","","Exfiltration Over Web Service","TA0010","Exfiltration","Exfiltrate to cloud storage","Linux,Windows,macOS",3),
    ("T1052","","Exfiltration Over Physical Medium","TA0010","Exfiltration","Exfiltrate via USB or physical media","Linux,Windows,macOS",3),
    ("T1486","","Data Encrypted for Impact","TA0040","Impact","Encrypt data for ransomware","Linux,Windows,macOS",4),
    ("T1490","","Inhibit System Recovery","TA0040","Impact","Delete backups disable recovery","Linux,Windows,macOS",4),
    ("T1485","","Data Destruction","TA0040","Impact","Destroy data to disrupt operations","Linux,Windows,macOS",4),
    ("T1491","","Defacement","TA0040","Impact","Modify web content for messaging","Linux,Windows,macOS",3),
    ("T1498","","Network Denial of Service","TA0040","Impact","Flood network to deny service","Linux,Windows,macOS",3),
    ("T1489","","Service Stop","TA0040","Impact","Stop critical services","Linux,Windows,macOS",3),
]

sev = {0:"Severity::Info",1:"Severity::Low",2:"Severity::Medium",
       3:"Severity::High",4:"Severity::Critical"}

for t in techniques:
    tid,sub,name,tactic,tname,desc,plat,sv = t
    cpp.append(f'    {{"{tid}","{sub}","{name}","{tactic}","{tname}",')
    cpp.append(f'     "{desc}","{plat}",{sev[sv]}}},')

cpp.append("};")
cpp.append("static constexpr std::size_t ENTERPRISE_COUNT =")
cpp.append("    sizeof(ENTERPRISE_DB)/sizeof(ENTERPRISE_DB[0]);")
cpp.append("")

# ICS
cpp.append("// ─── ICS database ────────────────────────────────────────────────────────")
cpp.append("static constexpr MitreTechnique ICS_DB[] = {")
ics = [
    ("T0800","","Activate Firmware Update Mode","TA0001","Initial Access","Exploit firmware update mechanism","ICS",3),
    ("T0801","","Monitor Process State","TA0007","Discovery","Monitor industrial process state","ICS",2),
    ("T0802","","Automated Collection","TA0009","Collection","Automated data collection from ICS","ICS",3),
    ("T0803","","Block Command Message","TA0005","Inhibit Response","Block legitimate control messages","ICS",4),
    ("T0804","","Block Reporting Message","TA0005","Inhibit Response","Block status reports to operators","ICS",4),
    ("T0806","","Brute Force I/O","TA0004","Impair Process","Force I/O to unsafe states","ICS",4),
    ("T0807","","Command-Line Interface","TA0002","Execution","Execute via CLI on ICS system","ICS",3),
    ("T0808","","Control Device","TA0004","Impair Process","Issue unauthorized control commands","ICS",4),
    ("T0810","","Data Historian Compromise","TA0008","Lateral Movement","Compromise data historian for pivot","ICS",4),
    ("T0812","","Default Credentials","TA0001","Initial Access","Use factory-default credentials","ICS",4),
    ("T0814","","Denial of Service","TA0040","Impact","Denial of service against ICS","ICS",4),
    ("T0816","","Device Restart/Shutdown","TA0040","Impact","Force restart or shutdown of ICS device","ICS",4),
    ("T0817","","Drive-by Compromise","TA0001","Initial Access","Compromise via malicious website","ICS",3),
    ("T0818","","Engineering Workstation Compromise","TA0001","Initial Access","Compromise ICS engineering workstation","ICS",4),
    ("T0819","","Exploit Public-Facing Application","TA0001","Initial Access","Exploit internet-facing ICS application","ICS",4),
    ("T0820","","Exploitation for Evasion","TA0005","Evasion","Exploit weakness to evade detection","ICS",3),
    ("T0821","","Modify Controller Tasking","TA0004","Impair Process","Change controller program logic","ICS",4),
    ("T0822","","External Remote Services","TA0001","Initial Access","Abuse remote access to ICS","ICS",3),
    ("T0823","","Graphical User Interface","TA0002","Execution","Use HMI or GUI for execution","ICS",3),
    ("T0824","","I/O Image","TA0009","Collection","Capture I/O image for analysis","ICS",3),
    ("T0825","","Location Identification","TA0007","Discovery","Identify physical process location","ICS",2),
    ("T0826","","Loss of Availability","TA0040","Impact","Cause loss of ICS availability","ICS",4),
    ("T0827","","Loss of Control","TA0040","Impact","Cause loss of process control","ICS",4),
    ("T0828","","Loss of Productivity and Revenue","TA0040","Impact","Disrupt production operations","ICS",4),
    ("T0829","","Loss of Protection","TA0040","Impact","Disable safety protection systems","ICS",4),
    ("T0830","","Adversary-in-the-Middle","TA0006","Collection","Intercept ICS communications","ICS",4),
    ("T0831","","Manipulation of Control","TA0040","Impact","Manipulate physical process control","ICS",4),
    ("T0832","","Manipulation of View","TA0005","Evasion","Manipulate operator view of process","ICS",4),
    ("T0833","","Measure Duration","TA0007","Discovery","Measure process duration","ICS",2),
    ("T0834","","Native API","TA0002","Execution","Use ICS native APIs","ICS",3),
    ("T0835","","Manipulate I/O Image","TA0004","Impair Process","Manipulate input/output image","ICS",4),
    ("T0836","","Modify Parameter","TA0004","Impair Process","Modify process parameter values","ICS",4),
    ("T0837","","Loss of Safety","TA0040","Impact","Cause loss of safety system function","ICS",4),
    ("T0838","","Modify Alarm Settings","TA0005","Inhibit Response","Disable or modify process alarms","ICS",4),
    ("T0839","","Module Firmware","TA0003","Persistence","Modify firmware for persistence","ICS",4),
    ("T0840","","Network Connection Enumeration","TA0007","Discovery","Enumerate ICS network connections","ICS",2),
    ("T0841","","Network Identification","TA0007","Discovery","Identify ICS network topology","ICS",2),
    ("T0842","","Network Sniffing","TA0006","Collection","Sniff ICS network traffic","ICS",3),
    ("T0843","","Program Download","TA0008","Lateral Movement","Download program from engineering workstation","ICS",4),
    ("T0844","","Program Organization Units","TA0007","Discovery","Discover ICS program structure","ICS",2),
    ("T0845","","Program Upload","TA0009","Collection","Upload ICS program for analysis","ICS",3),
    ("T0846","","Remote System Discovery","TA0007","Discovery","Discover remote ICS systems","ICS",2),
    ("T0847","","Replication Through Removable Media","TA0001","Initial Access","Spread via USB in air-gapped ICS","ICS",4),
    ("T0848","","Rogue Master","TA0004","Impair Process","Deploy rogue PLC or master device","ICS",4),
    ("T0849","","Masquerading","TA0005","Evasion","Masquerade as legitimate ICS process","ICS",3),
    ("T0850","","Role Identification","TA0007","Discovery","Identify roles of devices on ICS network","ICS",2),
    ("T0851","","Rootkit","TA0003","Persistence","Install rootkit on ICS system","ICS",4),
    ("T0852","","Screen Capture","TA0009","Collection","Capture HMI screen","ICS",3),
    ("T0853","","Scripting","TA0002","Execution","Execute scripts on ICS system","ICS",3),
    ("T0854","","Serial Connection Enumeration","TA0007","Discovery","Enumerate serial connections","ICS",2),
    ("T0855","","Unauthorized Command Message","TA0004","Impair Process","Send unauthorized control command","ICS",4),
    ("T0856","","Spoof Reporting Message","TA0005","Evasion","Spoof process data sent to operators","ICS",4),
    ("T0857","","System Firmware","TA0003","Persistence","Modify system firmware","ICS",4),
    ("T0858","","Change Credential","TA0003","Persistence","Change credentials for persistence","ICS",3),
    ("T0859","","Valid Accounts","TA0001","Initial Access","Use valid ICS credentials","ICS",3),
    ("T0860","","Wireless Compromise","TA0001","Initial Access","Compromise ICS wireless network","ICS",4),
    ("T0861","","Point and Tag Identification","TA0007","Discovery","Identify process control points","ICS",2),
    ("T0862","","Supply Chain Compromise","TA0001","Initial Access","Compromise ICS supply chain","ICS",4),
    ("T0863","","User Execution","TA0002","Execution","Trick ICS user into execution","ICS",3),
    ("T0864","","Transient Cyber Asset","TA0001","Initial Access","Compromise transient device connected to ICS","ICS",3),
    ("T0865","","Spearphishing Attachment","TA0001","Initial Access","Target ICS staff with phishing","ICS",3),
    ("T0866","","Exploitation of Remote Services","TA0008","Lateral Movement","Exploit remote services in ICS","ICS",4),
    ("T0867","","Lateral Tool Transfer","TA0008","Lateral Movement","Transfer tools laterally in ICS","ICS",3),
    ("T0868","","Detect Operating Mode","TA0007","Discovery","Detect ICS device operating mode","ICS",2),
    ("T0869","","Standard Application Layer Protocol","TA0011","Command and Control","Use standard ICS protocols for C2","ICS",3),
    ("T0870","","Exploitation for Privilege Escalation","TA0004","Privilege Escalation","Exploit ICS vulnerability for privesc","ICS",4),
    ("T0871","","Execution through API","TA0002","Execution","Execute via ICS API","ICS",3),
    ("T0872","","Indicator Removal on Host","TA0005","Evasion","Remove indicators from ICS host","ICS",3),
    ("T0873","","Project File Infection","TA0003","Persistence","Infect ICS project files","ICS",4),
    ("T0874","","Hooking","TA0004","Privilege Escalation","Hook ICS process for privilege","ICS",4),
    ("T0875","","Change Program State","TA0004","Impair Process","Change PLC program state","ICS",4),
    ("T0877","","I/O Module Discovery","TA0007","Discovery","Discover I/O modules on ICS network","ICS",2),
    ("T0878","","Alarm Suppression","TA0005","Inhibit Response","Suppress ICS alarms","ICS",4),
    ("T0879","","Damage to Property","TA0040","Impact","Cause physical damage via ICS","ICS",4),
    ("T0880","","Loss of View","TA0040","Impact","Cause operators to lose process visibility","ICS",4),
    ("T0881","","Service Stop","TA0040","Impact","Stop ICS services","ICS",4),
    ("T0882","","Theft of Operational Information","TA0009","Collection","Steal ICS operational data","ICS",3),
    ("T0883","","Internet Accessible Device","TA0001","Initial Access","Access ICS device exposed to internet","ICS",4),
    ("T0884","","Connection Proxy","TA0011","Command and Control","Use proxy for ICS C2","ICS",3),
    ("T0885","","Commonly Used Port","TA0011","Command and Control","Use common port for ICS C2","ICS",3),
    ("T0886","","Remote Services","TA0008","Lateral Movement","Remote services lateral movement in ICS","ICS",3),
    ("T0887","","Wireless Sniffing","TA0007","Discovery","Sniff ICS wireless communications","ICS",3),
    ("T0888","","Remote System Information Discovery","TA0007","Discovery","Gather info from remote ICS systems","ICS",2),
    ("T0889","","Modify Program","TA0004","Impair Process","Modify ICS control program","ICS",4),
    ("T0890","","Exploitation for Defense Evasion","TA0005","Evasion","Exploit ICS weakness to evade detection","ICS",3),
    ("T0891","","Hardcoded Credentials","TA0006","Credential Access","Use hardcoded ICS credentials","ICS",4),
    ("T0893","","Data from Local System","TA0009","Collection","Collect data from ICS local system","ICS",2),
]

for t in ics:
    tid,sub,name,tactic,tname,desc,plat,sv = t
    cpp.append(f'    {{"{tid}","","{name}","{tactic}","{tname}",')
    cpp.append(f'     "{desc}","{plat}",{sev[sv]}}},')

cpp.append("};")
cpp.append("static constexpr std::size_t ICS_COUNT =")
cpp.append("    sizeof(ICS_DB)/sizeof(ICS_DB[0]);")
cpp.append("")

# Actor table
cpp.append("// ─── Actor → technique IDs ───────────────────────────────────────────────")
cpp.append("struct ActorEntry {")
cpp.append("    const char* actor;")
cpp.append("    const char* technique_ids[20];")
cpp.append("    std::size_t count;")
cpp.append("};")
cpp.append("static constexpr ActorEntry ACTOR_DB[] = {")

actors = [
    ("APT28",    ["T1566","T1059","T1055","T1003","T1071","T1573","T1021","T1083","T1082","T1070"]),
    ("APT29",    ["T1566","T1059","T1078","T1003","T1071","T1573","T1550","T1021","T1027","T1070"]),
    ("APT41",    ["T1190","T1059","T1055","T1003","T1071","T1573","T1021","T1083","T1027","T1136"]),
    ("Lazarus",  ["T1566","T1059","T1055","T1003","T1486","T1041","T1573","T1021","T1027","T1070"]),
    ("LockBit",  ["T1486","T1490","T1059","T1078","T1021","T1083","T1560","T1070","T1027","T1547"]),
    ("FIN7",     ["T1566","T1059","T1055","T1003","T1071","T1021","T1056","T1560","T1027","T1204"]),
    ("Cobalt",   ["T1566","T1059","T1055","T1003","T1071","T1573","T1021","T1560","T1070","T1027"]),
    ("Sandworm", ["T1190","T1059","T1055","T1485","T1486","T1490","T1071","T1573","T1070","T1027"]),
    ("BlackCat", ["T1486","T1490","T1059","T1078","T1021","T1083","T1560","T1070","T1027","T1547"]),
    ("WizardSpider",["T1486","T1490","T1059","T1078","T1003","T1021","T1560","T1070","T1547","T1027"]),
    ("Kimsuky",  ["T1566","T1059","T1003","T1071","T1573","T1021","T1083","T1113","T1056","T1070"]),
    ("MuddyWater",["T1566","T1059","T1055","T1003","T1071","T1573","T1021","T1083","T1027","T1070"]),
]
for actor, tids in actors:
    padded = tids + [""]*(20-len(tids))
    ids_str = ", ".join([f'"{t}"' for t in padded])
    cpp.append(f'    {{"{actor}", {{{ids_str}}}, {len(tids)}}},')
cpp.append("};")
cpp.append("static constexpr std::size_t ACTOR_COUNT =")
cpp.append("    sizeof(ACTOR_DB)/sizeof(ACTOR_DB[0]);")
cpp.append("")

# Software table
cpp.append("// ─── Software → technique IDs ────────────────────────────────────────────")
cpp.append("static constexpr ActorEntry SOFTWARE_DB[] = {")
software = [
    ("Mimikatz",    ["T1003","T1550","T1558","T1555","T1134","T1059","T1027","T1070","T1083","T1082"]),
    ("CobaltStrike",["T1071","T1573","T1055","T1059","T1003","T1021","T1560","T1027","T1070","T1547"]),
    ("Metasploit",  ["T1190","T1059","T1055","T1003","T1021","T1560","T1027","T1070","T1136","T1547"]),
    ("Impacket",    ["T1003","T1550","T1021","T1558","T1059","T1083","T1082","T1560","T1070","T1136"]),
    ("BloodHound",  ["T1069","T1087","T1046","T1018","T1082","T1083","T1558","T1021","T1057","T1049"]),
    ("Sliver",      ["T1071","T1573","T1055","T1059","T1021","T1560","T1027","T1070","T1136","T1547"]),
    ("Empire",      ["T1059","T1055","T1003","T1071","T1573","T1021","T1560","T1027","T1070","T1547"]),
    ("BruteRatel",  ["T1071","T1573","T1055","T1059","T1003","T1021","T1560","T1027","T1070","T1547"]),
    ("Havoc",       ["T1071","T1573","T1055","T1059","T1003","T1021","T1560","T1027","T1070","T1547"]),
    ("Meterpreter", ["T1059","T1055","T1003","T1071","T1573","T1021","T1560","T1027","T1070","T1547"]),
    ("PsExec",      ["T1021","T1059","T1570","T1543","T1055","T1083","T1082","T1057","T1049","T1136"]),
    ("Nmap",        ["T1046","T1595","T1018","T1082","T1049","T1083","T1057","T1087","T1069","T1016"]),
]
for sw, tids in software:
    padded = tids + [""]*(20-len(tids))
    ids_str = ", ".join([f'"{t}"' for t in padded])
    cpp.append(f'    {{"{sw}", {{{ids_str}}}, {len(tids)}}},')
cpp.append("};")
cpp.append("static constexpr std::size_t SOFTWARE_COUNT =")
cpp.append("    sizeof(SOFTWARE_DB)/sizeof(SOFTWARE_DB[0]);")
cpp.append("")

# D3FEND
cpp.append("// ─── D3FEND countermeasures ──────────────────────────────────────────────")
cpp.append("struct D3fendEntry {")
cpp.append("    const char* technique_id;")
cpp.append("    const char* countermeasures[5];")
cpp.append("    std::size_t count;")
cpp.append("};")
cpp.append("static constexpr D3fendEntry D3FEND_DB[] = {")
d3fend = [
    ("T1566",["Email Filtering","Sender Reputation Analysis","Link Analysis","Attachment Analysis","User Training"]),
    ("T1190",["Web Application Firewall","Input Validation","Patch Management","Network Segmentation","Vulnerability Scanning"]),
    ("T1059",["Script Execution Analysis","Process Spawn Analysis","Application Allowlisting","Behavior Analysis","EDR"]),
    ("T1003",["Credential Hardening","LSASS Protection","Memory Protection","PAM","Privileged Account Management"]),
    ("T1071",["DNS Filtering","TLS Inspection","Network Traffic Analysis","Proxy Filtering","IDS/IPS"]),
    ("T1573",["TLS Inspection","Certificate Validation","Network Monitoring","Anomaly Detection","IDS"]),
    ("T1486",["Backup Strategy","Ransomware Detection","File Integrity Monitoring","EDR","Network Isolation"]),
    ("T1021",["Network Segmentation","Multi-Factor Authentication","PAM","Lateral Movement Detection","Zero Trust"]),
    ("T1550",["Credential Hardening","MFA","PAM","Anomaly Detection","Network Monitoring"]),
    ("T1558",["Kerberos Hardening","SPN Auditing","MFA","PAM","Network Monitoring"]),
    ("T1055",["Process Injection Detection","Memory Protection","EDR","Behavior Analysis","Allowlisting"]),
    ("T1048",["DNS Filtering","Data Loss Prevention","Network Monitoring","Egress Filtering","IDS"]),
]
for tid, cms in d3fend:
    padded = cms + [""]*(5-len(cms))
    cms_str = ", ".join([f'"{c}"' for c in padded])
    cpp.append(f'    {{"{tid}", {{{cms_str}}}, {len(cms)}}},')
cpp.append("};")
cpp.append("static constexpr std::size_t D3FEND_COUNT =")
cpp.append("    sizeof(D3FEND_DB)/sizeof(D3FEND_DB[0]);")
cpp.append("")

# Service table
cpp.append("// ─── Service → technique IDs ─────────────────────────────────────────────")
cpp.append("static constexpr ActorEntry SERVICE_DB[] = {")
services = [
    ("ssh",   ["T1021.004","T1110","T1078","T1098","T1136","T1550","T1566","T1190"]),
    ("rdp",   ["T1021.001","T1110","T1078","T1550","T1133","T1566","T1190","T1547"]),
    ("smb",   ["T1021.002","T1550","T1078","T1570","T1543","T1486","T1490","T1083"]),
    ("http",  ["T1190","T1505.003","T1059","T1566","T1189","T1199","T1027","T1083"]),
    ("https", ["T1190","T1505.003","T1071","T1573","T1566","T1189","T1027","T1083"]),
    ("ftp",   ["T1190","T1110","T1078","T1048","T1041","T1083","T1566","T1133"]),
    ("dns",   ["T1071.004","T1568","T1048","T1572","T1095","T1566","T1190","T1046"]),
    ("ldap",  ["T1087","T1069","T1558","T1018","T1046","T1082","T1083","T1057"]),
    ("mssql", ["T1190","T1110","T1078","T1059","T1083","T1082","T1136","T1078"]),
    ("mysql", ["T1190","T1110","T1078","T1059","T1083","T1082","T1136","T1078"]),
    ("winrm", ["T1021","T1059","T1078","T1550","T1110","T1136","T1543","T1083"]),
    ("snmp",  ["T1046","T1082","T1083","T1190","T1133","T1595","T1040","T1049"]),
    ("nfs",   ["T1190","T1083","T1078","T1021","T1048","T1560","T1570","T1136"]),
    ("vnc",   ["T1021","T1110","T1078","T1133","T1550","T1190","T1566","T1547"]),
    ("telnet",["T1190","T1110","T1078","T1021","T1059","T1083","T1082","T1040"]),
]
for svc, tids in services:
    padded = tids + [""]*(20-len(tids))
    ids_str = ", ".join([f'"{t}"' for t in padded])
    cpp.append(f'    {{"{svc}", {{{ids_str}}}, {len(tids)}}},')
cpp.append("};")
cpp.append("static constexpr std::size_t SERVICE_COUNT =")
cpp.append("    sizeof(SERVICE_DB)/sizeof(SERVICE_DB[0]);")
cpp.append("")

# Helper
cpp.append("// ─── Helpers ─────────────────────────────────────────────────────────────")
cpp.append("static bool iequal(const std::string& a,")
cpp.append("                   const char* b) noexcept {")
cpp.append("    std::string bs(b);")
cpp.append("    if (a.size() != bs.size()) return false;")
cpp.append("    for (std::size_t i = 0; i < a.size(); ++i)")
cpp.append("        if (tolower(static_cast<unsigned char>(a[i])) !=")
cpp.append("            tolower(static_cast<unsigned char>(bs[i])))")
cpp.append("            return false;")
cpp.append("    return true;")
cpp.append("}")
cpp.append("")

# Public API
cpp.append("// ─── Public API ───────────────────────────────────────────────────────────")
cpp.append("")
cpp.append("const MitreTechnique* MitreDb::lookup(")
cpp.append("    const std::string& id) noexcept {")
cpp.append("    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i) {")
cpp.append("        const auto& t = ENTERPRISE_DB[i];")
cpp.append("        if (id == t.id) return &t;")
cpp.append("        if (t.sub_id[0] != '\\0' && id == t.sub_id) return &t;")
cpp.append("    }")
cpp.append("    for (std::size_t i = 0; i < ICS_COUNT; ++i)")
cpp.append("        if (id == ICS_DB[i].id) return &ICS_DB[i];")
cpp.append("    return nullptr;")
cpp.append("}")
cpp.append("")
cpp.append("const MitreTechnique* MitreDb::lookup(")
cpp.append("    const TechniqueId& id) noexcept {")
cpp.append("    return lookup(id.value);")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<TechniqueRef>")
cpp.append("MitreDb::query(const MitreQuery& q) noexcept {")
cpp.append("    std::vector<TechniqueRef> result;")
cpp.append("    // Search Enterprise + ICS")
cpp.append("    auto check = [&](const MitreTechnique& t) {")
cpp.append("        if (q.tactic && *q.tactic != t.tactic) return;")
cpp.append("        if (q.min_severity &&")
cpp.append("            t.severity < *q.min_severity) return;")
cpp.append("        if (q.platform) {")
cpp.append("            std::string plat(t.platform);")
cpp.append("            if (plat.find(*q.platform) == std::string::npos)")
cpp.append("                return;")
cpp.append("        }")
cpp.append("        result.push_back(std::cref(t));")
cpp.append("    };")
cpp.append("    // Actor/software filter via their technique ID lists")
cpp.append("    if (q.actor) {")
cpp.append("        for (std::size_t i = 0; i < ACTOR_COUNT; ++i) {")
cpp.append("            if (!iequal(q.actor->value, ACTOR_DB[i].actor))")
cpp.append("                continue;")
cpp.append("            for (std::size_t j = 0; j < ACTOR_DB[i].count; ++j) {")
cpp.append("                auto* t = lookup(ACTOR_DB[i].technique_ids[j]);")
cpp.append("                if (t) check(*t);")
cpp.append("            }")
cpp.append("            return result;")
cpp.append("        }")
cpp.append("        return result; // actor not found")
cpp.append("    }")
cpp.append("    if (q.software) {")
cpp.append("        for (std::size_t i = 0; i < SOFTWARE_COUNT; ++i) {")
cpp.append("            if (!iequal(q.software->value, SOFTWARE_DB[i].actor))")
cpp.append("                continue;")
cpp.append("            for (std::size_t j = 0; j < SOFTWARE_DB[i].count; ++j) {")
cpp.append("                auto* t = lookup(SOFTWARE_DB[i].technique_ids[j]);")
cpp.append("                if (t) check(*t);")
cpp.append("            }")
cpp.append("            return result;")
cpp.append("        }")
cpp.append("        return result;")
cpp.append("    }")
cpp.append("    if (q.service) {")
cpp.append("        for (std::size_t i = 0; i < SERVICE_COUNT; ++i) {")
cpp.append("            if (!iequal(q.service->value, SERVICE_DB[i].actor))")
cpp.append("                continue;")
cpp.append("            for (std::size_t j = 0; j < SERVICE_DB[i].count; ++j) {")
cpp.append("                auto* t = lookup(SERVICE_DB[i].technique_ids[j]);")
cpp.append("                if (t) check(*t);")
cpp.append("            }")
cpp.append("            return result;")
cpp.append("        }")
cpp.append("        return result;")
cpp.append("    }")
cpp.append("    // No entity filter — scan all")
cpp.append("    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i)")
cpp.append("        check(ENTERPRISE_DB[i]);")
cpp.append("    for (std::size_t i = 0; i < ICS_COUNT; ++i)")
cpp.append("        check(ICS_DB[i]);")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::by_tactic(const std::string& tactic_id) noexcept {")
cpp.append("    std::vector<const MitreTechnique*> result;")
cpp.append("    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i)")
cpp.append("        if (tactic_id == ENTERPRISE_DB[i].tactic)")
cpp.append("            result.push_back(&ENTERPRISE_DB[i]);")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::by_actor(const std::string& actor) noexcept {")
cpp.append("    std::vector<const MitreTechnique*> result;")
cpp.append("    for (std::size_t i = 0; i < ACTOR_COUNT; ++i) {")
cpp.append("        if (!iequal(actor, ACTOR_DB[i].actor)) continue;")
cpp.append("        for (std::size_t j = 0; j < ACTOR_DB[i].count; ++j) {")
cpp.append("            auto* t = lookup(ACTOR_DB[i].technique_ids[j]);")
cpp.append("            if (t) result.push_back(t);")
cpp.append("        }")
cpp.append("        break;")
cpp.append("    }")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::by_software(const std::string& sw) noexcept {")
cpp.append("    std::vector<const MitreTechnique*> result;")
cpp.append("    for (std::size_t i = 0; i < SOFTWARE_COUNT; ++i) {")
cpp.append("        if (!iequal(sw, SOFTWARE_DB[i].actor)) continue;")
cpp.append("        for (std::size_t j = 0; j < SOFTWARE_DB[i].count; ++j) {")
cpp.append("            auto* t = lookup(SOFTWARE_DB[i].technique_ids[j]);")
cpp.append("            if (t) result.push_back(t);")
cpp.append("        }")
cpp.append("        break;")
cpp.append("    }")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::by_service(const std::string& svc) noexcept {")
cpp.append("    std::vector<const MitreTechnique*> result;")
cpp.append("    for (std::size_t i = 0; i < SERVICE_COUNT; ++i) {")
cpp.append("        if (!iequal(svc, SERVICE_DB[i].actor)) continue;")
cpp.append("        for (std::size_t j = 0; j < SERVICE_DB[i].count; ++j) {")
cpp.append("            auto* t = lookup(SERVICE_DB[i].technique_ids[j]);")
cpp.append("            if (t) result.push_back(t);")
cpp.append("        }")
cpp.append("        break;")
cpp.append("    }")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<std::string>")
cpp.append("MitreDb::d3fend_for(const std::string& tid) noexcept {")
cpp.append("    std::vector<std::string> result;")
cpp.append("    for (std::size_t i = 0; i < D3FEND_COUNT; ++i) {")
cpp.append("        if (tid != D3FEND_DB[i].technique_id) continue;")
cpp.append("        for (std::size_t j = 0; j < D3FEND_DB[i].count; ++j)")
cpp.append("            result.emplace_back(D3FEND_DB[i].countermeasures[j]);")
cpp.append("        break;")
cpp.append("    }")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("NavigatorLayer MitreDb::build_layer(")
cpp.append("    const std::vector<std::string>& technique_ids,")
cpp.append("    const std::string& layer_name,")
cpp.append("    const std::string& color) noexcept {")
cpp.append("    NavigatorLayer layer;")
cpp.append("    layer.name    = layer_name;")
cpp.append("    layer.domain  = \"enterprise-attack\";")
cpp.append("    layer.version = \"14\";")
cpp.append("    for (const auto& tid : technique_ids) {")
cpp.append("        NavigatorEntry e;")
cpp.append("        e.technique_id = TechniqueId{tid};")
cpp.append("        e.score        = 1.0f;")
cpp.append("        e.color        = color;")
cpp.append("        layer.techniques.push_back(std::move(e));")
cpp.append("    }")
cpp.append("    return layer;")
cpp.append("}")
cpp.append("")
cpp.append("std::string MitreDb::navigator_export(")
cpp.append("    const std::vector<std::string>& technique_ids,")
cpp.append("    const std::string& layer_name) noexcept {")
cpp.append("    return build_layer(technique_ids, layer_name).to_json();")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::ics_techniques() noexcept {")
cpp.append("    std::vector<const MitreTechnique*> result;")
cpp.append("    result.reserve(ICS_COUNT);")
cpp.append("    for (std::size_t i = 0; i < ICS_COUNT; ++i)")
cpp.append("        result.push_back(&ICS_DB[i]);")
cpp.append("    return result;")
cpp.append("}")
cpp.append("")
cpp.append("std::vector<const MitreTechnique*>")
cpp.append("MitreDb::mobile_techniques() noexcept {")
cpp.append("    // Mobile matrix planned for v0.2")
cpp.append("    return {};")
cpp.append("}")
cpp.append("")
cpp.append("std::size_t MitreDb::enterprise_size() noexcept {")
cpp.append("    return ENTERPRISE_COUNT;")
cpp.append("}")
cpp.append("")
cpp.append("std::size_t MitreDb::total_size() noexcept {")
cpp.append("    return ENTERPRISE_COUNT + ICS_COUNT;")
cpp.append("}")
cpp.append("")
cpp.append("const char* MitreDb::attack_version() noexcept {")
cpp.append("    return \"14\";")
cpp.append("}")
cpp.append("")
cpp.append("} // namespace zote")
cpp.append("")

pathlib.Path("src/mitre_map.cpp").write_text(
    "\n".join(cpp), encoding="utf-8")
print(f"OK -- src/mitre_map.cpp written ({len(cpp)} lines)")
print(f"     Enterprise: {len(techniques)} techniques")
print(f"     ICS:        {len(ics)} techniques")
print(f"     Actors:     {len(actors)}")
print(f"     Software:   {len(software)}")
print(f"     Services:   {len(services)}")
print(f"     D3FEND:     {len(d3fend)}")
