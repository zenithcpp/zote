// src/mitre_map.cpp
// ZOTE — zenithcpp Open Source Threat Engine
// ISO C++23 compliant — zero external dependencies
// Apache 2.0 License — https://github.com/zenithcpp/zote

#include <zote/mitre.hpp>
#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace zote {

// ─── Enterprise technique database ───────────────────────────────────────
static constexpr MitreTechnique ENTERPRISE_DB[] = {
    {"T1566","","Phishing","TA0001","Initial Access",
     "Adversaries send phishing emails to gain access","Linux,Windows,macOS",Severity::High},
    {"T1566","T1566.001","Spearphishing Attachment","TA0001","Initial Access",
     "Malicious file attachment in targeted email","Linux,Windows,macOS",Severity::Critical},
    {"T1566","T1566.002","Spearphishing Link","TA0001","Initial Access",
     "Malicious link in targeted email","Linux,Windows,macOS",Severity::High},
    {"T1190","","Exploit Public-Facing Application","TA0001","Initial Access",
     "Exploit weakness in internet-facing system","Linux,Windows,macOS",Severity::Critical},
    {"T1189","","Drive-by Compromise","TA0001","Initial Access",
     "Exploit browser visiting malicious website","Linux,Windows,macOS",Severity::High},
    {"T1199","","Trusted Relationship","TA0001","Initial Access",
     "Compromise via third-party trusted access","Linux,Windows,macOS",Severity::High},
    {"T1195","","Supply Chain Compromise","TA0001","Initial Access",
     "Compromise software supply chain","Linux,Windows,macOS",Severity::Critical},
    {"T1078","","Valid Accounts","TA0001","Initial Access",
     "Use legitimate credentials for access","Linux,Windows,macOS",Severity::High},
    {"T1133","","External Remote Services","TA0001","Initial Access",
     "Leverage VPN RDP or other remote services","Linux,Windows",Severity::High},
    {"T1059","","Command and Scripting Interpreter","TA0002","Execution",
     "Abuse command-line interfaces","Linux,Windows,macOS",Severity::High},
    {"T1059","T1059.001","PowerShell","TA0002","Execution",
     "Execute commands via PowerShell","Windows",Severity::High},
    {"T1059","T1059.003","Windows Command Shell","TA0002","Execution",
     "Execute via cmd.exe","Windows",Severity::Medium},
    {"T1059","T1059.004","Unix Shell","TA0002","Execution",
     "Execute via bash sh zsh","Linux,macOS",Severity::Medium},
    {"T1059","T1059.006","Python","TA0002","Execution",
     "Execute via Python interpreter","Linux,Windows,macOS",Severity::Medium},
    {"T1053","","Scheduled Task/Job","TA0002","Execution",
     "Abuse task scheduler for execution","Linux,Windows",Severity::High},
    {"T1053","T1053.005","Scheduled Task","TA0002","Execution",
     "Windows Task Scheduler abuse","Windows",Severity::High},
    {"T1053","T1053.003","Cron","TA0002","Execution",
     "Linux cron job abuse","Linux,macOS",Severity::High},
    {"T1106","","Native API","TA0002","Execution",
     "Use OS native APIs directly","Linux,Windows,macOS",Severity::High},
    {"T1204","","User Execution","TA0002","Execution",
     "Trick user into executing malicious content","Linux,Windows,macOS",Severity::High},
    {"T1547","","Boot/Logon Autostart Execution","TA0003","Persistence",
     "Configure at boot/logon execution","Linux,Windows,macOS",Severity::High},
    {"T1547","T1547.001","Registry Run Keys","TA0003","Persistence",
     "HKCU/HKLM run key persistence","Windows",Severity::High},
    {"T1543","","Create or Modify System Process","TA0003","Persistence",
     "Create malicious service or daemon","Linux,Windows,macOS",Severity::High},
    {"T1543","T1543.003","Windows Service","TA0003","Persistence",
     "Create or modify Windows service","Windows",Severity::High},
    {"T1546","","Event Triggered Execution","TA0003","Persistence",
     "Execute via system events","Linux,Windows,macOS",Severity::High},
    {"T1136","","Create Account","TA0003","Persistence",
     "Create local or domain account","Linux,Windows,macOS",Severity::High},
    {"T1505","","Server Software Component","TA0003","Persistence",
     "Install malicious web shell or plugin","Linux,Windows,macOS",Severity::Critical},
    {"T1505","T1505.003","Web Shell","TA0003","Persistence",
     "Deploy web shell for persistent access","Linux,Windows,macOS",Severity::Critical},
    {"T1068","","Exploitation for Privilege Escalation","TA0004","Privilege Escalation",
     "Exploit vulnerability to gain higher privileges","Linux,Windows,macOS",Severity::Critical},
    {"T1055","","Process Injection","TA0004","Privilege Escalation",
     "Inject code into another process","Linux,Windows,macOS",Severity::Critical},
    {"T1055","T1055.001","Dynamic-link Library Injection","TA0004","Privilege Escalation",
     "Inject DLL into process","Windows",Severity::Critical},
    {"T1548","","Abuse Elevation Control Mechanism","TA0004","Privilege Escalation",
     "Bypass UAC or sudo restrictions","Linux,Windows,macOS",Severity::High},
    {"T1548","T1548.003","Sudo and Sudo Caching","TA0004","Privilege Escalation",
     "Abuse sudo for privilege escalation","Linux,macOS",Severity::High},
    {"T1134","","Access Token Manipulation","TA0004","Privilege Escalation",
     "Steal or forge access tokens","Windows",Severity::Critical},
    {"T1070","","Indicator Removal","TA0005","Defense Evasion",
     "Remove indicators to avoid detection","Linux,Windows,macOS",Severity::High},
    {"T1070","T1070.004","File Deletion","TA0005","Defense Evasion",
     "Delete files to remove evidence","Linux,Windows,macOS",Severity::Medium},
    {"T1036","","Masquerading","TA0005","Defense Evasion",
     "Disguise malicious activity as legitimate","Linux,Windows,macOS",Severity::High},
    {"T1027","","Obfuscated Files or Information","TA0005","Defense Evasion",
     "Obfuscate content to evade detection","Linux,Windows,macOS",Severity::High},
    {"T1562","","Impair Defenses","TA0005","Defense Evasion",
     "Disable security tools","Linux,Windows,macOS",Severity::Critical},
    {"T1562","T1562.001","Disable or Modify Tools","TA0005","Defense Evasion",
     "Disable AV SIEM or EDR","Linux,Windows,macOS",Severity::Critical},
    {"T1112","","Modify Registry","TA0005","Defense Evasion",
     "Modify registry to hide or persist","Windows",Severity::High},
    {"T1003","","OS Credential Dumping","TA0006","Credential Access",
     "Dump OS credentials from memory or files","Linux,Windows,macOS",Severity::Critical},
    {"T1003","T1003.001","LSASS Memory","TA0006","Credential Access",
     "Dump credentials from LSASS","Windows",Severity::Critical},
    {"T1003","T1003.008","/etc/passwd and /etc/shadow","TA0006","Credential Access",
     "Read Linux password files","Linux",Severity::Critical},
    {"T1110","","Brute Force","TA0006","Credential Access",
     "Guess or crack credentials","Linux,Windows,macOS",Severity::High},
    {"T1110","T1110.003","Password Spraying","TA0006","Credential Access",
     "Try common passwords across many accounts","Linux,Windows,macOS",Severity::High},
    {"T1558","","Steal or Forge Kerberos Tickets","TA0006","Credential Access",
     "Steal or create Kerberos tickets","Windows",Severity::Critical},
    {"T1558","T1558.003","Kerberoasting","TA0006","Credential Access",
     "Request Kerberos TGS for offline cracking","Windows",Severity::Critical},
    {"T1555","","Credentials from Password Stores","TA0006","Credential Access",
     "Extract credentials from password stores","Linux,Windows,macOS",Severity::High},
    {"T1082","","System Information Discovery","TA0007","Discovery",
     "Enumerate system info OS version hardware","Linux,Windows,macOS",Severity::Medium},
    {"T1083","","File and Directory Discovery","TA0007","Discovery",
     "Enumerate files and directories","Linux,Windows,macOS",Severity::Medium},
    {"T1057","","Process Discovery","TA0007","Discovery",
     "Enumerate running processes","Linux,Windows,macOS",Severity::Medium},
    {"T1049","","System Network Connections Discovery","TA0007","Discovery",
     "Enumerate active network connections","Linux,Windows,macOS",Severity::Medium},
    {"T1087","","Account Discovery","TA0007","Discovery",
     "Enumerate local or domain accounts","Linux,Windows,macOS",Severity::Medium},
    {"T1046","","Network Service Discovery","TA0007","Discovery",
     "Scan network for open ports and services","Linux,Windows,macOS",Severity::High},
    {"T1018","","Remote System Discovery","TA0007","Discovery",
     "Enumerate remote systems on network","Linux,Windows,macOS",Severity::Medium},
    {"T1069","","Permission Groups Discovery","TA0007","Discovery",
     "Enumerate group memberships","Linux,Windows,macOS",Severity::Medium},
    {"T1021","","Remote Services","TA0008","Lateral Movement",
     "Use remote services for lateral movement","Linux,Windows,macOS",Severity::High},
    {"T1021","T1021.001","Remote Desktop Protocol","TA0008","Lateral Movement",
     "RDP lateral movement","Windows",Severity::High},
    {"T1021","T1021.002","SMB/Windows Admin Shares","TA0008","Lateral Movement",
     "SMB lateral movement","Windows",Severity::Critical},
    {"T1021","T1021.004","SSH","TA0008","Lateral Movement",
     "SSH lateral movement","Linux,macOS",Severity::High},
    {"T1550","","Use Alternate Authentication Material","TA0008","Lateral Movement",
     "Pass-the-hash pass-the-ticket","Windows",Severity::Critical},
    {"T1550","T1550.002","Pass the Hash","TA0008","Lateral Movement",
     "Authenticate using NTLM hash","Windows",Severity::Critical},
    {"T1550","T1550.003","Pass the Ticket","TA0008","Lateral Movement",
     "Authenticate using Kerberos ticket","Windows",Severity::Critical},
    {"T1534","","Internal Spearphishing","TA0008","Lateral Movement",
     "Phish internally after initial access","Linux,Windows,macOS",Severity::High},
    {"T1560","","Archive Collected Data","TA0009","Collection",
     "Archive data before exfiltration","Linux,Windows,macOS",Severity::High},
    {"T1074","","Data Staged","TA0009","Collection",
     "Stage data for exfiltration","Linux,Windows,macOS",Severity::High},
    {"T1056","","Input Capture","TA0009","Collection",
     "Capture keystrokes or credentials","Linux,Windows,macOS",Severity::High},
    {"T1113","","Screen Capture","TA0009","Collection",
     "Capture screen contents","Linux,Windows,macOS",Severity::Medium},
    {"T1071","","Application Layer Protocol","TA0011","Command and Control",
     "Use app layer protocols for C2","Linux,Windows,macOS",Severity::High},
    {"T1071","T1071.001","Web Protocols","TA0011","Command and Control",
     "HTTP/HTTPS C2 traffic","Linux,Windows,macOS",Severity::High},
    {"T1071","T1071.004","DNS","TA0011","Command and Control",
     "DNS tunneling for C2","Linux,Windows,macOS",Severity::Critical},
    {"T1573","","Encrypted Channel","TA0011","Command and Control",
     "Encrypt C2 communications","Linux,Windows,macOS",Severity::High},
    {"T1573","T1573.002","Asymmetric Cryptography","TA0011","Command and Control",
     "TLS/SSL encrypted C2","Linux,Windows,macOS",Severity::High},
    {"T1572","","Protocol Tunneling","TA0011","Command and Control",
     "Tunnel C2 over legitimate protocol","Linux,Windows,macOS",Severity::Critical},
    {"T1219","","Remote Access Software","TA0011","Command and Control",
     "Use commercial RAT for C2","Linux,Windows,macOS",Severity::High},
    {"T1090","","Proxy","TA0011","Command and Control",
     "Route C2 through proxy","Linux,Windows,macOS",Severity::High},
    {"T1095","","Non-Application Layer Protocol","TA0011","Command and Control",
     "Raw protocol C2 ICMP raw TCP","Linux,Windows,macOS",Severity::Critical},
    {"T1105","","Ingress Tool Transfer","TA0011","Command and Control",
     "Transfer tools to compromised system","Linux,Windows,macOS",Severity::High},
    {"T1041","","Exfiltration Over C2 Channel","TA0010","Exfiltration",
     "Exfiltrate data over existing C2","Linux,Windows,macOS",Severity::High},
    {"T1048","","Exfiltration Over Alternative Protocol","TA0010","Exfiltration",
     "Exfiltrate via DNS FTP SMTP","Linux,Windows,macOS",Severity::Critical},
    {"T1048","T1048.003","Exfiltration Over Unencrypted Protocol","TA0010","Exfiltration",
     "Exfiltrate via unencrypted channel","Linux,Windows,macOS",Severity::High},
    {"T1567","","Exfiltration Over Web Service","TA0010","Exfiltration",
     "Exfiltrate to cloud storage","Linux,Windows,macOS",Severity::High},
    {"T1052","","Exfiltration Over Physical Medium","TA0010","Exfiltration",
     "Exfiltrate via USB or physical media","Linux,Windows,macOS",Severity::High},
    {"T1486","","Data Encrypted for Impact","TA0040","Impact",
     "Encrypt data for ransomware","Linux,Windows,macOS",Severity::Critical},
    {"T1490","","Inhibit System Recovery","TA0040","Impact",
     "Delete backups disable recovery","Linux,Windows,macOS",Severity::Critical},
    {"T1485","","Data Destruction","TA0040","Impact",
     "Destroy data to disrupt operations","Linux,Windows,macOS",Severity::Critical},
    {"T1491","","Defacement","TA0040","Impact",
     "Modify web content for messaging","Linux,Windows,macOS",Severity::High},
    {"T1498","","Network Denial of Service","TA0040","Impact",
     "Flood network to deny service","Linux,Windows,macOS",Severity::High},
    {"T1489","","Service Stop","TA0040","Impact",
     "Stop critical services","Linux,Windows,macOS",Severity::High},
};
static constexpr std::size_t ENTERPRISE_COUNT =
    sizeof(ENTERPRISE_DB)/sizeof(ENTERPRISE_DB[0]);

// ─── ICS database ────────────────────────────────────────────────────────
static constexpr MitreTechnique ICS_DB[] = {
    {"T0800","","Activate Firmware Update Mode","TA0001","Initial Access",
     "Exploit firmware update mechanism","ICS",Severity::High},
    {"T0801","","Monitor Process State","TA0007","Discovery",
     "Monitor industrial process state","ICS",Severity::Medium},
    {"T0802","","Automated Collection","TA0009","Collection",
     "Automated data collection from ICS","ICS",Severity::High},
    {"T0803","","Block Command Message","TA0005","Inhibit Response",
     "Block legitimate control messages","ICS",Severity::Critical},
    {"T0804","","Block Reporting Message","TA0005","Inhibit Response",
     "Block status reports to operators","ICS",Severity::Critical},
    {"T0806","","Brute Force I/O","TA0004","Impair Process",
     "Force I/O to unsafe states","ICS",Severity::Critical},
    {"T0807","","Command-Line Interface","TA0002","Execution",
     "Execute via CLI on ICS system","ICS",Severity::High},
    {"T0808","","Control Device","TA0004","Impair Process",
     "Issue unauthorized control commands","ICS",Severity::Critical},
    {"T0810","","Data Historian Compromise","TA0008","Lateral Movement",
     "Compromise data historian for pivot","ICS",Severity::Critical},
    {"T0812","","Default Credentials","TA0001","Initial Access",
     "Use factory-default credentials","ICS",Severity::Critical},
    {"T0814","","Denial of Service","TA0040","Impact",
     "Denial of service against ICS","ICS",Severity::Critical},
    {"T0816","","Device Restart/Shutdown","TA0040","Impact",
     "Force restart or shutdown of ICS device","ICS",Severity::Critical},
    {"T0817","","Drive-by Compromise","TA0001","Initial Access",
     "Compromise via malicious website","ICS",Severity::High},
    {"T0818","","Engineering Workstation Compromise","TA0001","Initial Access",
     "Compromise ICS engineering workstation","ICS",Severity::Critical},
    {"T0819","","Exploit Public-Facing Application","TA0001","Initial Access",
     "Exploit internet-facing ICS application","ICS",Severity::Critical},
    {"T0820","","Exploitation for Evasion","TA0005","Evasion",
     "Exploit weakness to evade detection","ICS",Severity::High},
    {"T0821","","Modify Controller Tasking","TA0004","Impair Process",
     "Change controller program logic","ICS",Severity::Critical},
    {"T0822","","External Remote Services","TA0001","Initial Access",
     "Abuse remote access to ICS","ICS",Severity::High},
    {"T0823","","Graphical User Interface","TA0002","Execution",
     "Use HMI or GUI for execution","ICS",Severity::High},
    {"T0824","","I/O Image","TA0009","Collection",
     "Capture I/O image for analysis","ICS",Severity::High},
    {"T0825","","Location Identification","TA0007","Discovery",
     "Identify physical process location","ICS",Severity::Medium},
    {"T0826","","Loss of Availability","TA0040","Impact",
     "Cause loss of ICS availability","ICS",Severity::Critical},
    {"T0827","","Loss of Control","TA0040","Impact",
     "Cause loss of process control","ICS",Severity::Critical},
    {"T0828","","Loss of Productivity and Revenue","TA0040","Impact",
     "Disrupt production operations","ICS",Severity::Critical},
    {"T0829","","Loss of Protection","TA0040","Impact",
     "Disable safety protection systems","ICS",Severity::Critical},
    {"T0830","","Adversary-in-the-Middle","TA0006","Collection",
     "Intercept ICS communications","ICS",Severity::Critical},
    {"T0831","","Manipulation of Control","TA0040","Impact",
     "Manipulate physical process control","ICS",Severity::Critical},
    {"T0832","","Manipulation of View","TA0005","Evasion",
     "Manipulate operator view of process","ICS",Severity::Critical},
    {"T0833","","Measure Duration","TA0007","Discovery",
     "Measure process duration","ICS",Severity::Medium},
    {"T0834","","Native API","TA0002","Execution",
     "Use ICS native APIs","ICS",Severity::High},
    {"T0835","","Manipulate I/O Image","TA0004","Impair Process",
     "Manipulate input/output image","ICS",Severity::Critical},
    {"T0836","","Modify Parameter","TA0004","Impair Process",
     "Modify process parameter values","ICS",Severity::Critical},
    {"T0837","","Loss of Safety","TA0040","Impact",
     "Cause loss of safety system function","ICS",Severity::Critical},
    {"T0838","","Modify Alarm Settings","TA0005","Inhibit Response",
     "Disable or modify process alarms","ICS",Severity::Critical},
    {"T0839","","Module Firmware","TA0003","Persistence",
     "Modify firmware for persistence","ICS",Severity::Critical},
    {"T0840","","Network Connection Enumeration","TA0007","Discovery",
     "Enumerate ICS network connections","ICS",Severity::Medium},
    {"T0841","","Network Identification","TA0007","Discovery",
     "Identify ICS network topology","ICS",Severity::Medium},
    {"T0842","","Network Sniffing","TA0006","Collection",
     "Sniff ICS network traffic","ICS",Severity::High},
    {"T0843","","Program Download","TA0008","Lateral Movement",
     "Download program from engineering workstation","ICS",Severity::Critical},
    {"T0844","","Program Organization Units","TA0007","Discovery",
     "Discover ICS program structure","ICS",Severity::Medium},
    {"T0845","","Program Upload","TA0009","Collection",
     "Upload ICS program for analysis","ICS",Severity::High},
    {"T0846","","Remote System Discovery","TA0007","Discovery",
     "Discover remote ICS systems","ICS",Severity::Medium},
    {"T0847","","Replication Through Removable Media","TA0001","Initial Access",
     "Spread via USB in air-gapped ICS","ICS",Severity::Critical},
    {"T0848","","Rogue Master","TA0004","Impair Process",
     "Deploy rogue PLC or master device","ICS",Severity::Critical},
    {"T0849","","Masquerading","TA0005","Evasion",
     "Masquerade as legitimate ICS process","ICS",Severity::High},
    {"T0850","","Role Identification","TA0007","Discovery",
     "Identify roles of devices on ICS network","ICS",Severity::Medium},
    {"T0851","","Rootkit","TA0003","Persistence",
     "Install rootkit on ICS system","ICS",Severity::Critical},
    {"T0852","","Screen Capture","TA0009","Collection",
     "Capture HMI screen","ICS",Severity::High},
    {"T0853","","Scripting","TA0002","Execution",
     "Execute scripts on ICS system","ICS",Severity::High},
    {"T0854","","Serial Connection Enumeration","TA0007","Discovery",
     "Enumerate serial connections","ICS",Severity::Medium},
    {"T0855","","Unauthorized Command Message","TA0004","Impair Process",
     "Send unauthorized control command","ICS",Severity::Critical},
    {"T0856","","Spoof Reporting Message","TA0005","Evasion",
     "Spoof process data sent to operators","ICS",Severity::Critical},
    {"T0857","","System Firmware","TA0003","Persistence",
     "Modify system firmware","ICS",Severity::Critical},
    {"T0858","","Change Credential","TA0003","Persistence",
     "Change credentials for persistence","ICS",Severity::High},
    {"T0859","","Valid Accounts","TA0001","Initial Access",
     "Use valid ICS credentials","ICS",Severity::High},
    {"T0860","","Wireless Compromise","TA0001","Initial Access",
     "Compromise ICS wireless network","ICS",Severity::Critical},
    {"T0861","","Point and Tag Identification","TA0007","Discovery",
     "Identify process control points","ICS",Severity::Medium},
    {"T0862","","Supply Chain Compromise","TA0001","Initial Access",
     "Compromise ICS supply chain","ICS",Severity::Critical},
    {"T0863","","User Execution","TA0002","Execution",
     "Trick ICS user into execution","ICS",Severity::High},
    {"T0864","","Transient Cyber Asset","TA0001","Initial Access",
     "Compromise transient device connected to ICS","ICS",Severity::High},
    {"T0865","","Spearphishing Attachment","TA0001","Initial Access",
     "Target ICS staff with phishing","ICS",Severity::High},
    {"T0866","","Exploitation of Remote Services","TA0008","Lateral Movement",
     "Exploit remote services in ICS","ICS",Severity::Critical},
    {"T0867","","Lateral Tool Transfer","TA0008","Lateral Movement",
     "Transfer tools laterally in ICS","ICS",Severity::High},
    {"T0868","","Detect Operating Mode","TA0007","Discovery",
     "Detect ICS device operating mode","ICS",Severity::Medium},
    {"T0869","","Standard Application Layer Protocol","TA0011","Command and Control",
     "Use standard ICS protocols for C2","ICS",Severity::High},
    {"T0870","","Exploitation for Privilege Escalation","TA0004","Privilege Escalation",
     "Exploit ICS vulnerability for privesc","ICS",Severity::Critical},
    {"T0871","","Execution through API","TA0002","Execution",
     "Execute via ICS API","ICS",Severity::High},
    {"T0872","","Indicator Removal on Host","TA0005","Evasion",
     "Remove indicators from ICS host","ICS",Severity::High},
    {"T0873","","Project File Infection","TA0003","Persistence",
     "Infect ICS project files","ICS",Severity::Critical},
    {"T0874","","Hooking","TA0004","Privilege Escalation",
     "Hook ICS process for privilege","ICS",Severity::Critical},
    {"T0875","","Change Program State","TA0004","Impair Process",
     "Change PLC program state","ICS",Severity::Critical},
    {"T0877","","I/O Module Discovery","TA0007","Discovery",
     "Discover I/O modules on ICS network","ICS",Severity::Medium},
    {"T0878","","Alarm Suppression","TA0005","Inhibit Response",
     "Suppress ICS alarms","ICS",Severity::Critical},
    {"T0879","","Damage to Property","TA0040","Impact",
     "Cause physical damage via ICS","ICS",Severity::Critical},
    {"T0880","","Loss of View","TA0040","Impact",
     "Cause operators to lose process visibility","ICS",Severity::Critical},
    {"T0881","","Service Stop","TA0040","Impact",
     "Stop ICS services","ICS",Severity::Critical},
    {"T0882","","Theft of Operational Information","TA0009","Collection",
     "Steal ICS operational data","ICS",Severity::High},
    {"T0883","","Internet Accessible Device","TA0001","Initial Access",
     "Access ICS device exposed to internet","ICS",Severity::Critical},
    {"T0884","","Connection Proxy","TA0011","Command and Control",
     "Use proxy for ICS C2","ICS",Severity::High},
    {"T0885","","Commonly Used Port","TA0011","Command and Control",
     "Use common port for ICS C2","ICS",Severity::High},
    {"T0886","","Remote Services","TA0008","Lateral Movement",
     "Remote services lateral movement in ICS","ICS",Severity::High},
    {"T0887","","Wireless Sniffing","TA0007","Discovery",
     "Sniff ICS wireless communications","ICS",Severity::High},
    {"T0888","","Remote System Information Discovery","TA0007","Discovery",
     "Gather info from remote ICS systems","ICS",Severity::Medium},
    {"T0889","","Modify Program","TA0004","Impair Process",
     "Modify ICS control program","ICS",Severity::Critical},
    {"T0890","","Exploitation for Defense Evasion","TA0005","Evasion",
     "Exploit ICS weakness to evade detection","ICS",Severity::High},
    {"T0891","","Hardcoded Credentials","TA0006","Credential Access",
     "Use hardcoded ICS credentials","ICS",Severity::Critical},
    {"T0893","","Data from Local System","TA0009","Collection",
     "Collect data from ICS local system","ICS",Severity::Medium},
};
static constexpr std::size_t ICS_COUNT =
    sizeof(ICS_DB)/sizeof(ICS_DB[0]);

// ─── Actor → technique IDs ───────────────────────────────────────────────
struct ActorEntry {
    const char* actor;
    const char* technique_ids[20];
    std::size_t count;
};
static constexpr ActorEntry ACTOR_DB[] = {
    {"APT28", {"T1566", "T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1083", "T1082", "T1070", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"APT29", {"T1566", "T1059", "T1078", "T1003", "T1071", "T1573", "T1550", "T1021", "T1027", "T1070", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"APT41", {"T1190", "T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1083", "T1027", "T1136", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Lazarus", {"T1566", "T1059", "T1055", "T1003", "T1486", "T1041", "T1573", "T1021", "T1027", "T1070", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"LockBit", {"T1486", "T1490", "T1059", "T1078", "T1021", "T1083", "T1560", "T1070", "T1027", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"FIN7", {"T1566", "T1059", "T1055", "T1003", "T1071", "T1021", "T1056", "T1560", "T1027", "T1204", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Cobalt", {"T1566", "T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1560", "T1070", "T1027", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Sandworm", {"T1190", "T1059", "T1055", "T1485", "T1486", "T1490", "T1071", "T1573", "T1070", "T1027", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"BlackCat", {"T1486", "T1490", "T1059", "T1078", "T1021", "T1083", "T1560", "T1070", "T1027", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"WizardSpider", {"T1486", "T1490", "T1059", "T1078", "T1003", "T1021", "T1560", "T1070", "T1547", "T1027", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Kimsuky", {"T1566", "T1059", "T1003", "T1071", "T1573", "T1021", "T1083", "T1113", "T1056", "T1070", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"MuddyWater", {"T1566", "T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1083", "T1027", "T1070", "", "", "", "", "", "", "", "", "", ""}, 10},
};
static constexpr std::size_t ACTOR_COUNT =
    sizeof(ACTOR_DB)/sizeof(ACTOR_DB[0]);

// ─── Software → technique IDs ────────────────────────────────────────────
static constexpr ActorEntry SOFTWARE_DB[] = {
    {"Mimikatz", {"T1003", "T1550", "T1558", "T1555", "T1134", "T1059", "T1027", "T1070", "T1083", "T1082", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"CobaltStrike", {"T1071", "T1573", "T1055", "T1059", "T1003", "T1021", "T1560", "T1027", "T1070", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Metasploit", {"T1190", "T1059", "T1055", "T1003", "T1021", "T1560", "T1027", "T1070", "T1136", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Impacket", {"T1003", "T1550", "T1021", "T1558", "T1059", "T1083", "T1082", "T1560", "T1070", "T1136", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"BloodHound", {"T1069", "T1087", "T1046", "T1018", "T1082", "T1083", "T1558", "T1021", "T1057", "T1049", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Sliver", {"T1071", "T1573", "T1055", "T1059", "T1021", "T1560", "T1027", "T1070", "T1136", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Empire", {"T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1560", "T1027", "T1070", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"BruteRatel", {"T1071", "T1573", "T1055", "T1059", "T1003", "T1021", "T1560", "T1027", "T1070", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Havoc", {"T1071", "T1573", "T1055", "T1059", "T1003", "T1021", "T1560", "T1027", "T1070", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Meterpreter", {"T1059", "T1055", "T1003", "T1071", "T1573", "T1021", "T1560", "T1027", "T1070", "T1547", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"PsExec", {"T1021", "T1059", "T1570", "T1543", "T1055", "T1083", "T1082", "T1057", "T1049", "T1136", "", "", "", "", "", "", "", "", "", ""}, 10},
    {"Nmap", {"T1046", "T1595", "T1018", "T1082", "T1049", "T1083", "T1057", "T1087", "T1069", "T1016", "", "", "", "", "", "", "", "", "", ""}, 10},
};
static constexpr std::size_t SOFTWARE_COUNT =
    sizeof(SOFTWARE_DB)/sizeof(SOFTWARE_DB[0]);

// ─── D3FEND countermeasures ──────────────────────────────────────────────
struct D3fendEntry {
    const char* technique_id;
    const char* countermeasures[5];
    std::size_t count;
};
static constexpr D3fendEntry D3FEND_DB[] = {
    {"T1566", {"Email Filtering", "Sender Reputation Analysis", "Link Analysis", "Attachment Analysis", "User Training"}, 5},
    {"T1190", {"Web Application Firewall", "Input Validation", "Patch Management", "Network Segmentation", "Vulnerability Scanning"}, 5},
    {"T1059", {"Script Execution Analysis", "Process Spawn Analysis", "Application Allowlisting", "Behavior Analysis", "EDR"}, 5},
    {"T1003", {"Credential Hardening", "LSASS Protection", "Memory Protection", "PAM", "Privileged Account Management"}, 5},
    {"T1071", {"DNS Filtering", "TLS Inspection", "Network Traffic Analysis", "Proxy Filtering", "IDS/IPS"}, 5},
    {"T1573", {"TLS Inspection", "Certificate Validation", "Network Monitoring", "Anomaly Detection", "IDS"}, 5},
    {"T1486", {"Backup Strategy", "Ransomware Detection", "File Integrity Monitoring", "EDR", "Network Isolation"}, 5},
    {"T1021", {"Network Segmentation", "Multi-Factor Authentication", "PAM", "Lateral Movement Detection", "Zero Trust"}, 5},
    {"T1550", {"Credential Hardening", "MFA", "PAM", "Anomaly Detection", "Network Monitoring"}, 5},
    {"T1558", {"Kerberos Hardening", "SPN Auditing", "MFA", "PAM", "Network Monitoring"}, 5},
    {"T1055", {"Process Injection Detection", "Memory Protection", "EDR", "Behavior Analysis", "Allowlisting"}, 5},
    {"T1048", {"DNS Filtering", "Data Loss Prevention", "Network Monitoring", "Egress Filtering", "IDS"}, 5},
};
static constexpr std::size_t D3FEND_COUNT =
    sizeof(D3FEND_DB)/sizeof(D3FEND_DB[0]);

// ─── Service → technique IDs ─────────────────────────────────────────────
static constexpr ActorEntry SERVICE_DB[] = {
    {"ssh", {"T1021.004", "T1110", "T1078", "T1098", "T1136", "T1550", "T1566", "T1190", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"rdp", {"T1021.001", "T1110", "T1078", "T1550", "T1133", "T1566", "T1190", "T1547", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"smb", {"T1021.002", "T1550", "T1078", "T1570", "T1543", "T1486", "T1490", "T1083", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"http", {"T1190", "T1505.003", "T1059", "T1566", "T1189", "T1199", "T1027", "T1083", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"https", {"T1190", "T1505.003", "T1071", "T1573", "T1566", "T1189", "T1027", "T1083", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"ftp", {"T1190", "T1110", "T1078", "T1048", "T1041", "T1083", "T1566", "T1133", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"dns", {"T1071.004", "T1568", "T1048", "T1572", "T1095", "T1566", "T1190", "T1046", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"ldap", {"T1087", "T1069", "T1558", "T1018", "T1046", "T1082", "T1083", "T1057", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"mssql", {"T1190", "T1110", "T1078", "T1059", "T1083", "T1082", "T1136", "T1078", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"mysql", {"T1190", "T1110", "T1078", "T1059", "T1083", "T1082", "T1136", "T1078", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"winrm", {"T1021", "T1059", "T1078", "T1550", "T1110", "T1136", "T1543", "T1083", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"snmp", {"T1046", "T1082", "T1083", "T1190", "T1133", "T1595", "T1040", "T1049", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"nfs", {"T1190", "T1083", "T1078", "T1021", "T1048", "T1560", "T1570", "T1136", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"vnc", {"T1021", "T1110", "T1078", "T1133", "T1550", "T1190", "T1566", "T1547", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
    {"telnet", {"T1190", "T1110", "T1078", "T1021", "T1059", "T1083", "T1082", "T1040", "", "", "", "", "", "", "", "", "", "", "", ""}, 8},
};
static constexpr std::size_t SERVICE_COUNT =
    sizeof(SERVICE_DB)/sizeof(SERVICE_DB[0]);

// ─── Helpers ─────────────────────────────────────────────────────────────
static bool iequal(const std::string& a,
                   const char* b) noexcept {
    std::string bs(b);
    if (a.size() != bs.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (tolower(static_cast<unsigned char>(a[i])) !=
            tolower(static_cast<unsigned char>(bs[i])))
            return false;
    return true;
}

// ─── Public API ───────────────────────────────────────────────────────────

const MitreTechnique* MitreDb::lookup(
    const std::string& id) noexcept {
    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i) {
        const auto& t = ENTERPRISE_DB[i];
        if (id == t.id) return &t;
        if (t.sub_id[0] != '\0' && id == t.sub_id) return &t;
    }
    for (std::size_t i = 0; i < ICS_COUNT; ++i)
        if (id == ICS_DB[i].id) return &ICS_DB[i];
    return nullptr;
}

const MitreTechnique* MitreDb::lookup(
    const TechniqueId& id) noexcept {
    return lookup(id.value);
}

std::vector<TechniqueRef>
MitreDb::query(const MitreQuery& q) {
    std::vector<TechniqueRef> result;
    // Search Enterprise + ICS
    auto check = [&](const MitreTechnique& t) {
        if (q.tactic && *q.tactic != t.tactic) return;
        if (q.min_severity &&
            t.severity < *q.min_severity) return;
        if (q.platform) {
            std::string plat(t.platform);
            if (plat.find(*q.platform) == std::string::npos)
                return;
        }
        result.push_back(std::cref(t));
    };
    // Actor/software filter via their technique ID lists
    if (q.actor) {
        for (std::size_t i = 0; i < ACTOR_COUNT; ++i) {
            if (!iequal(q.actor->value, ACTOR_DB[i].actor))
                continue;
            for (std::size_t j = 0; j < ACTOR_DB[i].count; ++j) {
                auto* t = lookup(ACTOR_DB[i].technique_ids[j]);
                if (t) check(*t);
            }
            return result;
        }
        return result; // actor not found
    }
    if (q.software) {
        for (std::size_t i = 0; i < SOFTWARE_COUNT; ++i) {
            if (!iequal(q.software->value, SOFTWARE_DB[i].actor))
                continue;
            for (std::size_t j = 0; j < SOFTWARE_DB[i].count; ++j) {
                auto* t = lookup(SOFTWARE_DB[i].technique_ids[j]);
                if (t) check(*t);
            }
            return result;
        }
        return result;
    }
    if (q.service) {
        for (std::size_t i = 0; i < SERVICE_COUNT; ++i) {
            if (!iequal(q.service->value, SERVICE_DB[i].actor))
                continue;
            for (std::size_t j = 0; j < SERVICE_DB[i].count; ++j) {
                auto* t = lookup(SERVICE_DB[i].technique_ids[j]);
                if (t) check(*t);
            }
            return result;
        }
        return result;
    }
    // No entity filter — scan all
    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i)
        check(ENTERPRISE_DB[i]);
    for (std::size_t i = 0; i < ICS_COUNT; ++i)
        check(ICS_DB[i]);
    return result;
}

std::vector<const MitreTechnique*>
MitreDb::by_tactic(const std::string& tactic_id) {
    std::vector<const MitreTechnique*> result;
    for (std::size_t i = 0; i < ENTERPRISE_COUNT; ++i)
        if (tactic_id == ENTERPRISE_DB[i].tactic)
            result.push_back(&ENTERPRISE_DB[i]);
    return result;
}

std::vector<const MitreTechnique*>
MitreDb::by_actor(const std::string& actor) {
    std::vector<const MitreTechnique*> result;
    for (std::size_t i = 0; i < ACTOR_COUNT; ++i) {
        if (!iequal(actor, ACTOR_DB[i].actor)) continue;
        for (std::size_t j = 0; j < ACTOR_DB[i].count; ++j) {
            auto* t = lookup(ACTOR_DB[i].technique_ids[j]);
            if (t) result.push_back(t);
        }
        break;
    }
    return result;
}

std::vector<const MitreTechnique*>
MitreDb::by_software(const std::string& sw) {
    std::vector<const MitreTechnique*> result;
    for (std::size_t i = 0; i < SOFTWARE_COUNT; ++i) {
        if (!iequal(sw, SOFTWARE_DB[i].actor)) continue;
        for (std::size_t j = 0; j < SOFTWARE_DB[i].count; ++j) {
            auto* t = lookup(SOFTWARE_DB[i].technique_ids[j]);
            if (t) result.push_back(t);
        }
        break;
    }
    return result;
}

std::vector<const MitreTechnique*>
MitreDb::by_service(const std::string& svc) {
    std::vector<const MitreTechnique*> result;
    for (std::size_t i = 0; i < SERVICE_COUNT; ++i) {
        if (!iequal(svc, SERVICE_DB[i].actor)) continue;
        for (std::size_t j = 0; j < SERVICE_DB[i].count; ++j) {
            auto* t = lookup(SERVICE_DB[i].technique_ids[j]);
            if (t) result.push_back(t);
        }
        break;
    }
    return result;
}

std::vector<std::string>
MitreDb::d3fend_for(const std::string& tid) {
    std::vector<std::string> result;
    for (std::size_t i = 0; i < D3FEND_COUNT; ++i) {
        if (tid != D3FEND_DB[i].technique_id) continue;
        for (std::size_t j = 0; j < D3FEND_DB[i].count; ++j)
            result.emplace_back(D3FEND_DB[i].countermeasures[j]);
        break;
    }
    return result;
}

NavigatorLayer MitreDb::build_layer(
    const std::vector<std::string>& technique_ids,
    const std::string& layer_name,
    const std::string& color) noexcept {
    NavigatorLayer layer;
    layer.name    = layer_name;
    layer.domain  = "enterprise-attack";
    layer.version = "14";
    for (const auto& tid : technique_ids) {
        NavigatorEntry e;
        e.technique_id = TechniqueId{tid};
        e.score        = 1.0f;
        e.color        = color;
        layer.techniques.push_back(std::move(e));
    }
    return layer;
}

std::string MitreDb::navigator_export(
    const std::vector<std::string>& technique_ids,
    const std::string& layer_name) noexcept {
    return build_layer(technique_ids, layer_name).to_json();
}

std::vector<const MitreTechnique*>
MitreDb::ics_techniques() {
    std::vector<const MitreTechnique*> result;
    result.reserve(ICS_COUNT);
    for (std::size_t i = 0; i < ICS_COUNT; ++i)
        result.push_back(&ICS_DB[i]);
    return result;
}

std::vector<const MitreTechnique*>
MitreDb::mobile_techniques() {
    // Mobile matrix planned for v0.2
    return {};
}

std::size_t MitreDb::enterprise_size() noexcept {
    return ENTERPRISE_COUNT;
}

std::size_t MitreDb::total_size() noexcept {
    return ENTERPRISE_COUNT + ICS_COUNT;
}

const char* MitreDb::attack_version() noexcept {
    return "14";
}

} // namespace zote
