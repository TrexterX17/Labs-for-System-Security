# Lab 06: Windows Threat Hunting & Incident Response

## 📋 Lab Overview

**Difficulty Level:** Advanced  


### Objective
This lab demonstrates real-world incident response and threat hunting capabilities by investigating a security breach, analyzing attack vectors, identifying indicators of compromise (IoCs), removing malware and persistent mechanisms, and documenting findings in a professional incident report. This simulates actual SOC analyst responsibilities during a security incident.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Threat Hunting:** Proactive searching for security threats and anomalies
- **Incident Response:** Following IR lifecycle (Detection, Analysis, Containment, Eradication, Recovery)
- **Malware Analysis:** Identifying persistence mechanisms and malicious behavior
- **Windows Registry Forensics:** Investigating IFEO (Image File Execution Options) attacks
- **Security Log Analysis:** Reviewing Windows Event Logs for attack indicators
- **Remediation:** Removing malware, unauthorized accounts, and persistence mechanisms
- **Incident Documentation:** Writing professional incident reports for stakeholders
- **Post-Incident Analysis:** Lessons learned and security recommendations
- **Network Forensics:** Using `ss` command to identify suspicious connections

---

## 🛠️ Tools & Technologies Used

### Incident Response Tools
- **Windows Event Viewer** - Security log analysis and forensic investigation
- **Registry Editor (regedit)** - Windows Registry investigation and remediation
- **Task Manager** - Process monitoring and malware termination
- **Windows PowerShell** - User account management and forensic commands
- **Command Prompt** - System File Checker and remediation commands
- **System File Checker (sfc)** - Integrity verification and repair

### Forensic Analysis Techniques
| Technique | Purpose |
|-----------|---------|
| **Event Log Analysis** | Identify authentication attempts, user creation, suspicious activity |
| **Registry Forensics** | Discover persistence mechanisms (IFEO injection) |
| **Process Analysis** | Identify running malware and suspicious processes |
| **User Account Audit** | Detect unauthorized accounts and privilege escalation |
| **Network Analysis** | Identify command & control (C2) connections with `ss -tlp` |

### Windows Security Components
- **Event ID 4624** - Successful logon (identifies breach time)
- **Event ID 4720** - User account created (unauthorized account detection)
- **Event ID 4732** - Member added to security-enabled local group
- **IFEO Registry Key** - Image File Execution Options (common malware technique)

---

## 🔧 Incident Overview

### Attack Timeline

**Initial Breach:** February 27, 2022 at 4:48:49 PM

```
Timeline of Events:
├── 4:48:49 PM - Initial unauthorized access (brute force attack)
├── 4:59:00 PM - Malicious account "notbad" created via PowerShell
├── 5:05:00 PM - IFEO registry modification (taskmgr.exe hijacked)
├── 5:10:00 PM - Malware persistence mechanisms installed
└── 5:15:00 PM - Malicious GUI overlay deployed
```

### Incident Classification

**NIST Incident Categories:**
- Category: **CAT 2** - Unauthorized Access
- Severity: **High**
- Functional Impact: **Medium** (System management capability impaired)
- Information Impact: **Low** (No data exfiltration detected)

**Attack Vector:** Brute Force Authentication Attack

**Systems Affected:**
- **Hostname:** DESKTOP-CHO0HOF
- **User Impacted:** Jim
- **Domain:** 3D Printing and Pizza network

---

## 📝 Threat Hunting Methodology

### Phase 1: Initial Detection & Analysis

#### Indicator 1: Task Manager Hijacking (IFEO Injection)

**Symptom:**
Attempting to launch Task Manager opens Notepad with random text instead.

**Filename:** Taskmgr (mimicking legitimate Task Manager)

**Technical Analysis:**

**What is IFEO (Image File Execution Options)?**
- Windows Registry key used for debugging applications
- Legitimate use: Attach debugger to program when it launches
- Malicious use: Redirect program execution to different binary

**Attack Mechanism:**
```
Registry Path: 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe

Malicious Entry:
Debugger = "notepad.exe"

Result:
When user launches taskmgr.exe → Windows launches notepad.exe instead
```

**Why This Attack?**
- Prevents victims from using Task Manager to:
  - View running processes (malware would be visible)
  - Kill malicious processes
  - Monitor system performance
  - Investigate suspicious activity

**Real-World Examples:**
- Used by ransomware to prevent termination
- Deployed by RATs (Remote Access Trojans) for persistence
- Common in targeted attacks to impair incident response

**Detection Method:**
```powershell
# Check for IFEO registry keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# Look for debugger values
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" | 
  Where-Object {$_.Debugger} | Select-Object PSPath, Debugger
```

#### Indicator 2: Persistent GUI Overlay

**Symptom:**
Popup window in center of screen displaying: "Nothing to see here, I am a good software"
- Cannot be closed with X button
- Cannot be closed with OK button
- Stays on top of all windows

**Technical Analysis:**

**Purpose of Overlay:**
1. **Distraction:** Keeps user focused on annoying popup
2. **Social Engineering:** Message designed to appear innocent
3. **Anti-Forensics:** Distracts from investigating actual malware
4. **Persistence Testing:** Validates malware is running

**Implementation:**
Likely a PowerShell or AutoHotkey script creating always-on-top window.

**Process Identification:**
Found in Task Manager as background process (after IFEO remediated).

#### Indicator 3: Unauthorized User Account

**Account Name:** notbad
**Created:** February 27, 2022 at 4:59 PM (11 minutes after initial breach)

**PowerShell Command Used:**
```powershell
net user notbad password321 /add
```

**Why Create Backdoor Account?**
1. **Persistence:** Maintains access even if initial entry point closed
2. **Privilege Escalation:** Can be added to Administrators group
3. **Lateral Movement:** Used to access other systems on network
4. **Deniability:** Blends in with legitimate user accounts

**Detection in Event Logs:**

**Event ID 4720:** User Account Created
```
Subject:
  Security ID: DESKTOP-CHO0HOF\Jim
  Account Name: Jim

New Account:
  Security ID: DESKTOP-CHO0HOF\notbad
  Account Name: notbad
  
Process Information:
  Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Red Flags:**
- Account created via PowerShell (unusual for legitimate admins)
- Weak password (password321 - easily guessable)
- Created during off-hours or immediately after breach
- Name designed to appear benign ("notbad" = "not bad" = "good")

#### Indicator 4: Brute Force Authentication

**Evidence in Security Logs:**

**Event ID 4625:** Failed Logon Attempts
Multiple entries showing:
```
Logon Type: 3 (Network)
Failure Reason: Unknown username or bad password
Source Network Address: [Attacker IP]
Workstation Name: [Attacker System]
```

**Event ID 4624:** Successful Logon
```
Time: 2/27/2022 4:48:49 PM
Account Name: Jim
Logon Type: 3 (Network)
Source Network Address: [Attacker IP]
```

**Brute Force Pattern:**
- Multiple failed attempts (Event ID 4625)
- Followed by successful authentication (Event ID 4624)
- Indicates password guessing attack succeeded

**Why Brute Force Succeeded:**
- Weak password policy (likely simple password)
- No account lockout policy configured
- No multi-factor authentication
- No rate limiting on authentication attempts

#### Indicator 5: Persistent Malware Files

**File 1:** Deep files associated with "notbad" user
- Location: C:\Users\notbad\*
- Purpose: User profile for backdoor account
- Contains: Desktop files, AppData, registry hives

**File 2:** IMPORTANTSECURITYTOOLDONOTDELETEPLEASE
- Location: Unknown (likely C:\Windows\System32 or startup folder)
- Name: Social engineering attempt (appears important)
- Purpose: Persistence mechanism or additional payload

**Common Malware Hiding Locations:**
```
C:\Windows\System32\           (Blends with legitimate files)
C:\Windows\Temp\               (Temporary files, often ignored)
C:\ProgramData\                (Hidden folder)
C:\Users\[User]\AppData\Roaming\  (User-specific persistence)
HKLM\Software\Microsoft\Windows\CurrentVersion\Run  (Registry autostart)
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\  (Startup folder)
```

---

### Phase 2: Containment & Eradication

#### Remediation Step 1: Remove IFEO Registry Hijack

**Process:**
1. Open Registry Editor (regedit.exe) as Administrator
2. Navigate to:
   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
   ```
3. Locate "taskmgr.exe" key
4. Right-click → Delete

**Verification:**
```powershell
# Verify taskmgr.exe key removed
Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
# Should return: False
```

**Alternative Command-Line Remediation:**
```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f
```

**Why This Works:**
- Removes registry redirection
- Task Manager will now launch normally
- Restores system management capability

**Post-Remediation:**
Task Manager now launches correctly, allowing process investigation.

#### Remediation Step 2: System File Integrity Check

**Command:**
```cmd
sfc /scannow
```

**What This Does:**
- **SFC:** System File Checker
- Scans all protected system files
- Compares against cached copies in C:\Windows\WinSxS
- Replaces corrupted files with correct versions
- Verifies Windows system integrity

**Output Interpretation:**
```
Windows Resource Protection found corrupt files and successfully repaired them.
Details are included in the CBS.Log windir\Logs\CBS\CBS.log

OR

Windows Resource Protection did not find any integrity violations.
```

**Why This Step?**
- Malware may have modified system files
- Ensures Task Manager binary is legitimate
- Verifies no rootkit components installed
- Required before declaring system clean

**Alternative/Additional Checks:**
```powershell
# DISM - Deployment Image Servicing and Management (more thorough)
DISM /Online /Cleanup-Image /RestoreHealth

# Check specific file integrity
sfc /verifyfile=C:\Windows\System32\taskmgr.exe
```

#### Remediation Step 3: Terminate Malicious GUI Process

**Process:**
1. Open Task Manager (now functional after IFEO removal)
2. Locate suspicious process:
   - Name may be generic (e.g., "Script Host", "PowerShell")
   - Check "Command Line" column for suspicious parameters
   - Look for processes with no publisher or description
3. Select malicious process
4. Click "End Task"

**Identification Tips:**
```
Suspicious Process Characteristics:
- No digital signature or publisher
- High CPU/memory usage without purpose
- Command line with obfuscated code
- Parent process is unusual (e.g., PowerShell launched by cmd)
- Connections to unknown external IPs
```

**Verification:**
Popup window should disappear after process termination.

**Forensic Value:**
Before terminating, note:
- Process ID (PID)
- Full command line
- Parent process
- Network connections (netstat -ano | findstr [PID])
- File location

#### Remediation Step 4: Remove Unauthorized User Account

**Command:**
```powershell
Remove-LocalUser -Name "notbad"
```

**Verification:**
```powershell
Get-LocalUser | Where-Object {$_.Name -eq "notbad"}
# Should return nothing
```

**Additional Checks:**
```powershell
# Check if account was added to Administrators group
Get-LocalGroupMember -Group "Administrators"

# Review all local accounts for other suspicious entries
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
```

**Why Remove Account?**
- Eliminates persistent access mechanism
- Prevents attacker from returning
- Removes potential privilege escalation path

**Complete User Removal:**
```powershell
# Remove user account
Remove-LocalUser -Name "notbad"

# Remove user profile folder
Remove-Item "C:\Users\notbad" -Recurse -Force

# Clean up registry references
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*notbad*" -Recurse -Force
```

#### Remediation Step 5: Remove Persistent Malware

**File 1: User Profile Cleanup**
```powershell
# Remove all files associated with backdoor account
Remove-Item "C:\Users\notbad" -Recurse -Force

# Verify removal
Test-Path "C:\Users\notbad"  # Should return False
```

**File 2: Remove "Important Security Tool"**
```powershell
# Locate the file first
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
  Where-Object {$_.Name -like "*IMPORTANTSECURITYTOOL*"}

# Remove found files
Remove-Item "C:\Path\To\IMPORTANTSECURITYTOOLDONOTDELETEPLEASE" -Force
```

**Check Startup Locations:**
```powershell
# Registry Run keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Startup folder
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*"}
```

**Remove Persistence Mechanisms:**
```powershell
# Remove malicious registry keys
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousEntry"

# Remove malicious scheduled tasks
Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false

# Remove malicious services
Stop-Service "MaliciousService"
sc.exe delete "MaliciousService"
```

---

### Phase 3: Network Forensics (Additional Task)

#### Linux Network Connection Analysis

**Command:**
```bash
ss -tlp
```

**Flag Breakdown:**
- **ss:** Socket Statistics (modern replacement for netstat)
- **-t:** TCP connections only
- **-l:** Listening sockets
- **-p:** Show process using socket

**Example Output:**
```
State    Recv-Q Send-Q Local Address:Port    Peer Address:Port    Process
LISTEN   0      128    0.0.0.0:22            0.0.0.0:*            users:(("sshd",pid=1234,fd=3))
LISTEN   0      128    0.0.0.0:80            0.0.0.0:*            users:(("apache2",pid=5678,fd=4))
ESTAB    0      0      10.43.32.11:54321     8.8.8.8:443          users:(("firefox",pid=9012,fd=56))
```

**What to Look For (Suspicious Indicators):**

**1. Unusual Listening Ports:**
```
LISTEN   0      128    0.0.0.0:4444          0.0.0.0:*            users:(("nc",pid=9999,fd=3))
```
- Port 4444: Common Metasploit default port
- Process: nc (netcat) - often used by attackers
- Action: Kill process, investigate origin

**2. Connections to Unknown IPs:**
```
ESTAB    0      0      10.43.32.11:12345     45.67.89.10:443      users:(("unknown",pid=8888,fd=10))
```
- Unknown external IP (check threat intel)
- Unrecognized process name
- Action: Terminate, block IP at firewall

**3. Suspicious Process Names:**
```
LISTEN   0      128    0.0.0.0:31337         0.0.0.0:*            users:(("backdoor",pid=7777,fd=5))
```
- Port 31337 (leet speak) - common hacker port
- Obvious suspicious name
- Action: Kill immediately, full investigation

**Remediation:**
```bash
# Kill suspicious process
sudo kill -9 [PID]

# Block malicious IP at firewall (iptables)
sudo iptables -A INPUT -s 45.67.89.10 -j DROP

# Remove malware binary
sudo rm /path/to/malicious/binary

# Check for persistence
sudo crontab -l
sudo systemctl list-units --type=service
```

**Additional Network Forensics:**
```bash
# All connections (not just listening)
ss -tanp

# Established connections only
ss -tanp state established

# Show process tree
ps auxf

# Network statistics
netstat -s

# Find which process is using specific port
lsof -i :4444
```

---

## 🎓 Incident Report Documentation

### Executive Summary

**Incident Type:** Unauthorized Access via Brute Force Attack

**Impact:**
- Unauthorized user account created ("notbad")
- System management tools compromised (Task Manager hijacked)
- Persistence mechanisms installed
- Potential for data exfiltration or lateral movement

**Remediation Status:** ✅ Complete
- IFEO registry hijack removed
- Unauthorized account deleted
- Malware files removed
- System integrity verified

**Recommendation:** Systems should undergo additional security hardening before returning to production.

### Business Impact Assessment

**Functional Impact: MEDIUM**
- **Immediate:** Loss of Task Manager access impaired troubleshooting
- **Potential:** Complete system compromise if not detected
- **Scope:** Single workstation (DESKTOP-CHO0HOF)

**Information Impact: LOW (Unconfirmed)**
- No evidence of data exfiltration in logs
- Malware focused on persistence, not data theft
- However, attacker had user-level access for ~30 minutes

**Recoverability: SUPPLEMENTED**
- System recovered with manual intervention
- Time to recovery: ~2 hours
- Requires additional security controls before production use

### Root Cause Analysis

**Primary Cause:** Weak Authentication Security
1. No password complexity requirements
2. No account lockout policy
3. No multi-factor authentication
4. User education lacking (weak password chosen)

**Contributing Factors:**
1. No anomaly detection/alerting
2. Delayed incident detection
3. No endpoint protection (antivirus/EDR)
4. Excessive user privileges

### Lessons Learned

**What Worked Well:**
- Event log analysis provided clear attack timeline
- Registry forensics revealed persistence mechanism
- System File Checker validated system integrity
- Documentation enabled knowledge sharing

**What Needs Improvement:**
1. **Detection:** No alerting on brute force attempts
2. **Prevention:** Weak password policy allowed breach
3. **Response:** Incident detected by user, not security tools
4. **Containment:** No automated isolation of compromised system

### Recommendations

**Immediate Actions (0-30 days):**

**1. Password Policy Enforcement:**
```
Minimum length: 12 characters
Complexity: Uppercase + lowercase + numbers + symbols
Maximum age: 90 days
History: Remember 24 passwords
Account lockout: 5 failed attempts, 30-minute lockout
```

**2. Multi-Factor Authentication:**
- Deploy MFA for all user accounts
- Require MFA for administrative actions
- Use authenticator app or hardware tokens

**3. Principle of Least Privilege:**
- Remove administrative rights from standard users
- Use separate admin accounts for privileged tasks
- Implement Just-In-Time (JIT) access

**4. Endpoint Detection and Response (EDR):**
- Deploy EDR solution (CrowdStrike, Carbon Black, Defender ATP)
- Enable real-time malware detection
- Configure automated response actions

**Short-Term Actions (30-90 days):**

**5. Security Awareness Training:**
- Phishing awareness
- Password hygiene
- Recognizing suspicious activity
- Reporting procedures

**6. Security Information and Event Management (SIEM):**
- Centralize log collection
- Create alerts for brute force attempts
- Monitor for IFEO registry changes
- Alert on unauthorized user creation

**7. Vulnerability Management:**
- Regular patch management
- Monthly vulnerability scans
- Prioritize critical vulnerabilities

**Long-Term Actions (90+ days):**

**8. Penetration Testing:**
- Annual penetration tests
- Red team exercises
- Tabletop incident response drills

**9. Zero Trust Architecture:**
- Micro-segmentation
- Continuous verification
- Assume breach mentality

**10. Incident Response Plan:**
- Documented IR procedures
- Defined roles and responsibilities
- Communication plan
- Playbooks for common scenarios

---

## 🔐 Indicators of Compromise (IoCs)

### File-Based IoCs

**Registry Keys:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe
  Debugger = "notepad.exe"
```

**Files:**
```
C:\Users\notbad\*  (All files - backdoor account)
C:\[Path]\IMPORTANTSECURITYTOOLDONOTDELETEPLEASE
```

**User Accounts:**
```
notbad  (Created: 2/27/2022 4:59 PM)
```

### Network-Based IoCs

**Suspicious Connections (if detected):**
```
Outbound connections to unknown IPs on high ports
Listening services on non-standard ports (e.g., 4444, 31337)
```

### Behavioral IoCs

**Event Log Patterns:**
```
Event ID 4625: Multiple failed logon attempts from same source
Event ID 4624: Successful logon after failed attempts
Event ID 4720: User account created via PowerShell
Event ID 4732: User added to Administrators group
```

**Process Indicators:**
```
notepad.exe launched instead of taskmgr.exe
PowerShell commands: net user [user] [password] /add
Persistent popup window process
```

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**SOC Analyst (Tier 1/2) ($65K-$95K):**
- Monitor security alerts and logs
- Investigate suspicious activity
- Document incidents professionally
- Escalate to senior analysts
- Follow incident response procedures

**Incident Responder ($85K-$120K):**
- Lead incident investigations
- Perform malware analysis
- Coordinate remediation efforts
- Create detailed incident reports
- Recommend security improvements

**Threat Hunter ($90K-$130K):**
- Proactively search for threats
- Analyze attack patterns
- Identify persistence mechanisms
- Develop detection signatures
- Improve security posture

**Digital Forensics Analyst ($80K-$115K):**
- Analyze Windows artifacts
- Investigate registry forensics
- Timeline analysis from event logs
- Chain of custody documentation
- Expert witness testimony

### Enterprise Scenarios

**Scenario 1: Ransomware Response**
```
Detection: User reports encrypted files
Analysis: Event logs show account creation, IFEO changes
Containment: Isolate infected systems, block C2 IP
Eradication: Remove malware, restore from backups
Recovery: Validate systems, return to production
Lessons Learned: Implement offline backups, email filtering
```

**Scenario 2: Insider Threat**
```
Detection: Unusual data access patterns
Analysis: Event logs show after-hours activity
Containment: Suspend user account, preserve evidence
Eradication: Remove unauthorized access
Recovery: Restore proper permissions
Lessons Learned: Implement DLP, user behavior analytics
```

**Scenario 3: APT (Advanced Persistent Threat)**
```
Detection: EDR alerts on living-off-the-land techniques
Analysis: IFEO injection, scheduled tasks, registry persistence
Containment: Network segmentation, block attacker infrastructure
Eradication: Hunt for all persistence mechanisms across network
Recovery: Rebuild compromised systems from known-good images
Lessons Learned: Implement threat intelligence, conduct IR drills
```

---

## 📚 Commands Reference

### Windows Forensics

**Event Log Analysis:**
```powershell
# View Security logs
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 10

# Failed logon attempts
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}

# User account created
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4720}

# Export logs
wevtutil epl Security C:\logs\security.evtx
```

**Registry Investigation:**
```cmd
# List IFEO keys
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# Check specific program
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"

# Delete malicious key
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f
```

**User Account Forensics:**
```powershell
# List all local users
Get-LocalUser

# User creation history
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4720}

# Check user group membership
Get-LocalGroupMember -Group "Administrators"

# Remove malicious user
Remove-LocalUser -Name "notbad"
```

**System Integrity:**
```cmd
# System File Checker
sfc /scannow

# DISM repair
DISM /Online /Cleanup-Image /RestoreHealth

# Check specific file
sfc /verifyfile=C:\Windows\System32\taskmgr.exe
```

### Linux Network Forensics

```bash
# Socket statistics
ss -tanp              # All TCP connections with process info
ss -tulpn             # TCP/UDP listening ports
ss -o state established  # Established connections with timers

# Process investigation
ps auxf               # Process tree
lsof -i               # Open network files
netstat -antp         # Alternative to ss

# Kill malicious process
kill -9 [PID]

# Block attacker IP
iptables -A INPUT -s [ATTACKER_IP] -j DROP
```

---

## 💡 Lessons Learned

### Technical Insights

1. **IFEO is Common Malware Technique**
   - Easy to implement
   - Difficult for average users to detect
   - Effective at preventing Task Manager use
   - Can be applied to any executable

2. **Brute Force Still Works**
   - Weak passwords remain #1 vulnerability
   - Account lockout is essential
   - MFA would have prevented this entirely

3. **Event Logs Are Critical**
   - Complete attack timeline available
   - Shows attacker commands and actions
   - Essential for incident investigation
   - Must be protected from deletion/tampering

4. **Persistence is Multi-Layered**
   - Attackers create multiple backdoors
   - Registry, scheduled tasks, services, accounts
   - Must hunt thoroughly for all mechanisms

5. **Social Engineering in Malware**
   - "Nothing to see here" message
   - "IMPORTANTSECURITYTOOL" filename
   - Designed to manipulate victims
   - Security awareness training helps

### Professional Practices

1. **Document Everything**
   - Screenshots of evidence
   - Commands executed
   - Timeline of actions
   - Findings and analysis

2. **Follow Incident Response Process**
   - Detection → Analysis → Containment → Eradication → Recovery
   - Don't skip steps
   - Preserve evidence

3. **Assume Compromise is Deeper**
   - Don't trust system after breach
   - Hunt for additional persistence
   - Verify integrity thoroughly

4. **Communication is Critical**
   - Incident reports for stakeholders
   - Technical details for responders
   - Recommendations for prevention

---

## 🔗 Related Technologies

### Incident Response Tools

**EDR (Endpoint Detection and Response):**
- **CrowdStrike Falcon** - Cloud-native EDR
- **Carbon Black** - Behavioral analysis
- **Microsoft Defender ATP** - Windows-integrated
- **SentinelOne** - Autonomous response

**SIEM (Security Information and Event Management):**
- **Splunk** - Industry standard
- **IBM QRadar** - Enterprise SIEM
- **Microsoft Sentinel** - Cloud-native
- **ELK Stack** - Open-source alternative

**Forensics:**
- **EnCase** - Disk imaging and analysis
- **FTK (Forensic Toolkit)** - Complete forensic suite
- **Volatility** - Memory forensics
- **Autopsy** - Open-source digital forensics

**Malware Analysis:**
- **IDA Pro** - Disassembler and debugger
- **Ghidra** - NSA's reverse engineering tool
- **Any.run** - Interactive malware sandbox
- **VirusTotal** - Multi-engine malware scanner

### Industry Certifications

**Incident Response:**
- **GCIH** - GIAC Certified Incident Handler
- **GCFA** - GIAC Certified Forensic Analyst
- **GCFE** - GIAC Certified Forensic Examiner
- **CHFI** - Computer Hacking Forensic Investigator

**Threat Hunting:**
- **GCIA** - GIAC Certified Intrusion Analyst
- **GCTI** - GIAC Cyber Threat Intelligence
- **BTL1** - Blue Team Level 1

**General Security:**
- **CompTIA Security+** - Includes incident response
- **CISSP** - Domain 7: Security Operations
- **CEH** - Certified Ethical Hacker

---

## 📸 Lab Evidence

All screenshots documented in original incident report:

**Indicators of Compromise:**
- ✅ Malicious Notepad (Task Manager hijack)
- ✅ Persistent popup message
- ✅ Security event logs (brute force, user creation)
- ✅ PowerShell command history (notbad creation)

**Remediation Actions:**
- ✅ Registry Editor (IFEO key deletion)
- ✅ System File Checker execution
- ✅ Task Manager (malware termination)
- ✅ Malicious user account removal
- ✅ Persistent malware file deletion

**Network Forensics:**
- ✅ Linux socket statistics (ss -tlp)

---

## 🏆 Lab Status

**Incident Status:** ✅ Resolved  
**Malware Removed:** ✅ All persistence mechanisms eradicated  
**System Integrity:** ✅ Verified with SFC  
**Recommendations:** ✅ Documented for management  
**Incident Report:** ✅ Professional documentation complete

---

## 🔍 Troubleshooting Guide

### Common Issues in Incident Response

**Issue 1: Cannot Access Registry Editor**
```
Symptoms: regedit.exe won't launch or is disabled
Solution:
- Check for IFEO hijack on regedit.exe itself
- Use Group Policy: gpedit.msc → User Config → Admin Templates
  → System → Prevent access to registry editing tools (Disable)
- Alternative: Use reg.exe from command line
```

**Issue 2: System File Checker Fails**
```
Symptoms: SFC reports errors but can't fix
Solution:
- Run DISM first: DISM /Online /Cleanup-Image /RestoreHealth
- Boot into Safe Mode and retry SFC
- Check disk for errors: chkdsk /f /r
```

**Issue 3: Malware Persists After Removal**
```
Symptoms: Malware returns after reboot
Solution:
- Check ALL persistence locations:
  - Registry Run keys (HKLM and HKCU)
  - Startup folders
  - Scheduled tasks
  - Services
  - WMI event consumers
- Use Sysinternals Autoruns to find all autostart locations
```

**Issue 4: Cannot Delete Malicious Files**
```
Symptoms: "File in use" or "Access denied" errors
Solution:
- Boot into Safe Mode
- Use Process Explorer to identify locking process
- Take ownership: takeown /f [file] /r /d y
- Grant permissions: icacls [file] /grant administrators:F
```

---
## 📋 Incident Report Summary

**INCIDENT #:** 2024-032  
**CLASSIFICATION:** CAT 2 - Unauthorized Access  
**SEVERITY:** High  
**STATUS:** Closed/Resolved  
**INVESTIGATOR:** Faraz Ahmed  
**DATE:** Winter 2025

**EXECUTIVE SUMMARY:**
Security breach involving brute force authentication attack, unauthorized account creation, and malware installation with persistence mechanisms. All malicious artifacts successfully removed. System integrity verified. Comprehensive security recommendations provided to prevent future incidents.

**BUSINESS IMPACT:** Medium functional impact (system management impaired), Low information impact (no confirmed data exfiltration), Supplemented recoverability (manual intervention required).

**REMEDIATION:** Complete. Unauthorized user removed, IFEO hijack eliminated, malware eradicated, system integrity validated.

**RECOMMENDATIONS:** Implement password policy, multi-factor authentication, EDR solution, security awareness training, and SIEM for continuous monitoring.
