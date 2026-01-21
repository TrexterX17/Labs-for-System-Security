# Lab 03: Firewall Configuration & Access Control

## 📋 Lab Overview
  
**Difficulty Level:** Intermediate/Advanced  


### Objective
This lab demonstrates advanced firewall configuration skills by implementing granular access control policies on pfSense, creating inbound and outbound firewall rules, establishing least-privilege administrative access, and testing rule effectiveness through systematic validation. This simulates real-world security operations where network access must be tightly controlled while maintaining business functionality.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Firewall Rule Creation:** Configuring protocol-specific inbound and outbound rules
- **Access Control Implementation:** Establishing least-privilege network access policies
- **Security Hardening:** Restricting administrative access to designated systems only
- **Protocol Understanding:** Working with WinRM, RDP, SSH, FTP, HTTP/HTTPS, and DNS
- **Rule Testing & Validation:** Systematically verifying firewall rule effectiveness
- **Security Documentation:** Writing professional security policy memos
- **Threat Mitigation:** Preventing unauthorized access while maintaining functionality

---

## 🛠️ Tools & Technologies Used

### Firewall Platform
- **pfSense CE 2.7.2** - Enterprise-grade open-source firewall/router
- **pfSense Web Configurator** - GUI-based firewall management interface

### Protocols Configured
| Protocol | Port(s) | Purpose | Direction |
|----------|---------|---------|-----------|
| **WinRM** | 5985 (HTTP), 5986 (HTTPS) | Windows Remote Management | Inbound |
| **RDP** | 3389 | Remote Desktop Protocol | Inbound |
| **SSH** | 22 | Secure Shell remote access | Inbound |
| **FTP** | 21 | File Transfer Protocol | Outbound |
| **HTTP** | 80 | Web traffic (unencrypted) | Outbound |
| **HTTPS** | 443 | Web traffic (encrypted) | Outbound |
| **DNS** | 53 | Domain Name System | Outbound |
| **ICMP** | N/A | Internet Control Message Protocol (ping) | Outbound |
| **Windows Update** | Various | Microsoft update services | Outbound |

### Testing Tools
| Tool | Platform | Purpose |
|------|----------|---------|
| `ping` | Windows/Linux | ICMP connectivity testing |
| `Test-WSMan` | PowerShell | WinRM connectivity validation |
| `Remote Desktop Connection` | Windows | RDP functionality testing |
| `PuTTY` | Windows | SSH client for remote access |
| `ftp` | Command-line | FTP protocol testing |
| Web Browsers | Both | HTTP/HTTPS testing |

---

## 🔧 Lab Environment Architecture

### Network Topology

```
                    [Internet]
                        |
                  [External IF]
                  192.168.254.254
                        |
                  [pfSense Router]
                  🔥 FIREWALL RULES 🔥
                        |
        +---------------+---------------+
        |                               |
    [AdminNet IF]                 [ServerNet IF]
    10.42.32.1/24                10.43.32.0/24
        |                               |
    +---+---+                      [Ubuntu Server]
    |       |                      10.43.32.11
[Win10] [OutsideDevice]
10.42.32.12  10.42.32.X
```

### Key Network Components

**AdminNet Devices:**
- **Windows 10 Client:** 10.42.32.12 (Primary admin workstation)
- **OutsideDevice:** 10.42.32.X (Simulated external/untrusted device)

**ServerNet Devices:**
- **Ubuntu Client:** 10.43.32.11 (Server infrastructure)

**pfSense Router:**
- **AdminNet Gateway:** 10.42.32.1
- **ServerNet Gateway:** 10.43.32.1
- **External Gateway:** Dynamic/192.168.254.254

---

## 📝 Methodology & Implementation

### Phase 1: Inbound Firewall Rules (AdminNet)

Inbound rules control what traffic is **allowed INTO** the AdminNet network from external sources.

#### Rule 1: WinRM (Windows Remote Management)

**Configuration:**
- **Protocol:** TCP
- **Source:** OutsideDevice IP
- **Source Port:** Any (*)
- **Destination:** Windows 10 Client (10.42.32.12)
- **Destination Port:** 5985 (HTTP), 5986 (HTTPS)
- **Action:** Allow

**What is WinRM?**
Windows Remote Management is Microsoft's implementation of the WS-Management protocol, allowing administrators to:
- Execute commands remotely on Windows systems
- Manage Windows servers without physical access
- Automate system administration tasks
- Integrate with PowerShell remoting

**Security Consideration:**
- Port 5985 (HTTP) transmits data in plaintext - vulnerable to eavesdropping
- Port 5986 (HTTPS) encrypts traffic - recommended for production
- Source IP restriction limits exposure to specific management hosts

**Real-World Use Case:**
System administrators use WinRM to manage hundreds of Windows servers from a central management console (like PowerShell remoting or SCCM).

#### Rule 2: RDP (Remote Desktop Protocol)

**Configuration:**
- **Protocol:** TCP
- **Source:** OutsideDevice IP or specific admin IPs
- **Destination:** Windows 10 Client (10.42.32.12)
- **Destination Port:** 3389
- **Action:** Allow

**What is RDP?**
Remote Desktop Protocol allows full graphical remote access to Windows systems, enabling:
- Remote GUI-based system administration
- Remote technical support
- Access to applications running on remote systems

**Security Implications:**
- RDP has been a frequent attack vector (brute force, exploits)
- Should ALWAYS be restricted by source IP
- Enable Network Level Authentication (NLA) for additional security
- Consider using VPN before allowing RDP access

**Best Practice:** 
In production environments, RDP should only be accessible:
1. From jump boxes/bastion hosts
2. Through VPN connections
3. With multi-factor authentication enabled

#### Rule 3: SSH (Secure Shell)

**Configuration:**
- **Protocol:** TCP
- **Source:** OutsideDevice IP or specific admin IPs
- **Destination:** Ubuntu Server (10.43.32.11) or other SSH-enabled hosts
- **Destination Port:** 22
- **Action:** Allow

**What is SSH?**
Secure Shell provides encrypted remote command-line access to Unix/Linux systems, supporting:
- Secure remote terminal access
- Secure file transfer (SFTP/SCP)
- Port forwarding and tunneling
- Public key authentication

**Why SSH is Preferred:**
- All traffic is encrypted by default
- Supports key-based authentication (more secure than passwords)
- Industry standard for Linux/Unix administration
- Built-in to nearly all Linux distributions

**Security Best Practices:**
- Disable password authentication (use SSH keys only)
- Change default port 22 to non-standard port (security through obscurity)
- Implement fail2ban to prevent brute force attacks
- Use SSH certificates for enterprise environments

#### Summary of Inbound Rules

**Purpose:** These rules allow **remote administration** of systems within AdminNet from specific external sources (like IT administrator workstations).

**Security Principle:** **Least Privilege Access**
- Only specific protocols are allowed (not all traffic)
- Only from specific source IPs (not the entire internet)
- Only to specific destination systems (not the entire network)

---

### Phase 2: Outbound Firewall Rules (AdminNet)

Outbound rules control what traffic is **allowed OUT OF** the AdminNet network to external destinations.

#### Rule 1: FTP (File Transfer Protocol)

**Configuration:**
- **Protocol:** TCP
- **Source:** AdminNet network (10.42.32.0/24)
- **Source Port:** Any (*)
- **Destination:** Any
- **Destination Port:** 21 (Control), 20 (Data)
- **Action:** Allow

**What is FTP?**
File Transfer Protocol enables file exchange between systems:
- Upload/download files to/from FTP servers
- Anonymous or authenticated access
- Active vs Passive modes (important for firewall configuration)

**Security Concerns:**
- **Plaintext Protocol:** Credentials and data transmitted unencrypted
- **Recommended Alternative:** SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure)
- **Modern Replacement:** HTTPS-based file sharing

**Why Still Allowed?**
- Legacy systems may require FTP
- Some vendors only provide FTP access
- Demonstrates understanding of protocol-specific rules

**Firewall Complexity:**
FTP is particularly challenging for firewalls because:
- Uses two connections (control and data)
- Passive mode requires dynamic port ranges
- Requires ALG (Application Layer Gateway) support

#### Rule 2: HTTP/HTTPS (Web Traffic)

**Configuration:**
- **Protocol:** TCP
- **Source:** AdminNet network (10.42.32.0/24)
- **Destination:** Any
- **Destination Port:** 80 (HTTP), 443 (HTTPS)
- **Action:** Allow

**Purpose:** 
- Access websites and web applications
- Essential for modern business operations
- Required for cloud-based services

**HTTP vs HTTPS:**
| Feature | HTTP (Port 80) | HTTPS (Port 443) |
|---------|----------------|------------------|
| Encryption | ❌ No | ✅ Yes (TLS/SSL) |
| Data Integrity | ❌ Vulnerable | ✅ Protected |
| Authentication | ❌ None | ✅ Certificate-based |
| SEO Ranking | Lower | Higher |
| Browser Warning | Yes (Chrome) | No |

**Modern Security Requirement:**
- Most websites now mandate HTTPS
- Browsers display warnings for HTTP sites
- Many services refuse HTTP connections entirely

#### Rule 3: DNS (Domain Name System)

**Configuration:**
- **Protocol:** UDP (primarily), TCP (for large responses)
- **Source:** AdminNet network (10.42.32.0/24)
- **Destination:** DNS servers (8.8.8.8, 8.8.4.4)
- **Destination Port:** 53
- **Action:** Allow

**Why DNS is Critical:**
- Translates domain names (google.com) to IP addresses
- Required for virtually all internet communication
- Without DNS, users must remember IP addresses

**DNS Security Considerations:**
- **DNS Hijacking:** Attackers redirect DNS queries to malicious servers
- **DNS Tunneling:** Attackers exfiltrate data through DNS queries
- **Cache Poisoning:** Corrupting DNS cache with false entries
- **Modern Solution:** DNS over HTTPS (DoH) or DNS over TLS (DoT)

**Recommended Practice:**
- Use trusted DNS servers (Google 8.8.8.8, Cloudflare 1.1.1.1)
- Implement DNSSEC for validation
- Monitor DNS queries for anomalies

#### Rule 4: ICMP (Internet Control Message Protocol)

**Configuration:**
- **Protocol:** ICMP
- **Source:** AdminNet network (10.42.32.0/24)
- **Destination:** Any
- **Action:** Allow

**What is ICMP?**
Network diagnostic protocol supporting:
- **Ping:** Echo request/reply for connectivity testing
- **Traceroute:** Path discovery to destinations
- **Error Messages:** Network unreachable, TTL exceeded

**Common Security Debate:**
**Should ICMP be blocked?**

**Arguments for Blocking:**
- Prevents network reconnaissance (ping sweeps)
- Hides existence of systems
- Prevents certain DoS attacks (ping floods)

**Arguments for Allowing:**
- Essential for network troubleshooting
- Legitimate diagnostic tool
- Many applications expect ICMP responses
- Blocking creates "false negative" troubleshooting scenarios

**Best Practice:** Allow outbound ICMP, carefully control inbound ICMP

#### Rule 5: Windows Update

**Configuration:**
- **Protocol:** HTTPS (TCP)
- **Source:** AdminNet network (10.42.32.0/24)
- **Destination:** Microsoft update servers (various)
- **Destination Port:** 443
- **Action:** Allow

**Critical Security Requirement:**
- Systems must receive security patches
- Unpatched systems are vulnerable to known exploits
- Windows Update is essential for security compliance

**Enterprise Considerations:**
- Use WSUS (Windows Server Update Services) for centralized control
- Stage updates in test environment before production
- Schedule update windows to minimize disruption
- Monitor update compliance across fleet

**Alternative Approach:**
In enterprise environments, instead of allowing direct internet access for updates:
1. Windows clients connect to internal WSUS server
2. WSUS server (in DMZ) downloads from Microsoft
3. Provides update control and bandwidth management

---

### Phase 3: Administrative Access Control

#### Security Challenge: The "Anti-Lockout" Problem

**Default pfSense Behavior:**
- "Anti-Lockout" rule automatically allows **all** AdminNet devices to access pfSense web interface
- **Security Risk:** Any compromised device on AdminNet can manage the firewall
- **Solution:** Designate ONE specific management workstation

#### Step 1: Disable Anti-Lockout Rule

**Configuration Path:** System → Advanced → Anti-Lockout

**Why Disable It?**
- The anti-lockout rule is too permissive
- Allows any device on LAN to manage firewall
- Violates principle of least privilege
- Should be replaced with explicit, restrictive rule

**Warning:** 
⚠️ Only disable after creating replacement rule, or you'll be locked out!

#### Step 2: Create Explicit Management Rule

**Configuration:**
- **Protocol:** TCP
- **Source:** Windows 10 Client ONLY (10.42.32.12)
- **Destination:** pfSense (This Firewall)
- **Destination Port:** 443 (HTTPS)
- **Action:** Allow
- **Position:** Top of rule list (evaluated first)

**Security Principle: Explicit Deny**
After the allow rule for Win10Client, all other devices are **implicitly denied** (default deny policy).

#### Step 3: Create Explicit Block Rules (Optional but Recommended)

**Additional Security:**
Create explicit DENY rules for other devices before the allow rule:
- **Source:** OutsideDevice IP
- **Destination:** pfSense
- **Action:** Block/Reject
- **Logging:** Enabled (to detect unauthorized attempts)

**Rule Order Matters:**
```
1. Allow Win10Client → pfSense HTTPS (port 443)
2. Block OutsideDevice → pfSense (all ports)
3. Block UbuntuClient → pfSense (all ports)
4. [Implicit deny all other traffic]
```

**Why This Approach?**
- **Defense in Depth:** Explicit blocks plus implicit deny
- **Audit Trail:** Logging shows unauthorized access attempts
- **Clear Intent:** Documentation shows deliberate security decisions

#### SSH Access Control

**Same Principle for SSH (Port 22):**
- Only Win10Client can SSH to pfSense
- All other devices denied
- Prevents unauthorized command-line access

**Why Control Both Web and CLI Access?**
- Web GUI (HTTPS) - Configuration changes
- CLI (SSH) - Advanced troubleshooting, scripting
- Both provide full administrative control
- Both must be restricted to authorized systems

---

### Phase 4: Firewall Rule Summary & Documentation

#### External Interface Rules

**Purpose:** Control traffic entering from the internet

**Typical Rules:**
1. **Block RFC1918 Private IPs** - Prevent IP spoofing
2. **Block Bogon Networks** - Block reserved/unallocated IPs
3. **Allow Established/Related** - Return traffic for outbound connections
4. **Default Deny** - Block all other inbound traffic

**Security Note:** 
External interface should have **very restrictive** inbound rules. Most organizations block ALL inbound traffic unless explicitly required (like port forwarding for services).

#### AdminNet Interface Rules

**Implemented Rules:**

**Inbound (TO AdminNet):**
1. ✅ WinRM (5985/5986) - From OutsideDevice to Win10Client
2. ✅ RDP (3389) - Remote desktop access
3. ✅ SSH (22) - Secure shell access
4. ✅ ICMP - Ping/diagnostic traffic

**Outbound (FROM AdminNet):**
1. ✅ FTP (21) - File transfer
2. ✅ HTTP/HTTPS (80/443) - Web browsing
3. ✅ DNS (53) - Name resolution
4. ✅ Windows Update - Security patches
5. ✅ ICMP - Network diagnostics

**Management Rules:**
1. ✅ Win10Client → pfSense HTTPS (443)
2. ✅ Win10Client → pfSense SSH (22)
3. ❌ All others → pfSense (blocked)

#### ServerNet Interface Rules

**Purpose:** Control traffic to/from server infrastructure

**Typical Configuration:**
- More restrictive than AdminNet
- Only required server protocols allowed
- Inter-VLAN rules for AdminNet → ServerNet communication
- Monitoring and logging enabled

**Common Server Protocols:**
- HTTP/HTTPS (80/443) - Web servers
- MySQL (3306) - Database servers
- PostgreSQL (5432) - Database servers
- SMTP (25/587) - Mail servers
- DNS (53) - DNS servers

---

## 🔍 Testing & Validation

### Testing Methodology

**Systematic Approach:**
1. **Test Expected Success:** Verify allowed traffic works
2. **Test Expected Failure:** Verify blocked traffic is denied
3. **Test Edge Cases:** Verify rule boundaries
4. **Document Results:** Screenshot evidence for audit trail

---

### Test Suite 1: AdminNet Outbound Protocol Testing

#### Test 1.1: ICMP Connectivity

**Command:**
```cmd
ping 8.8.8.8
```

**Expected Result:** ✅ Success (replies received)

**What This Validates:**
- ICMP outbound rule is working
- Default gateway is reachable
- Internet connectivity established
- Routing is functioning correctly

**Troubleshooting if Failed:**
- Check ICMP outbound rule exists and is enabled
- Verify rule is not blocked by rule higher in list
- Check gateway configuration
- Verify DNS resolution (if using hostname instead of IP)

#### Test 1.2: HTTPS/DNS (Encrypted Web Traffic)

**Test Method:** 
Navigate to `https://www.ftx.com` in web browser

**Expected Result:** ✅ Website loads successfully

**What This Validates:**
- HTTPS outbound rule (port 443) is working
- DNS resolution is functioning (domain → IP)
- TCP three-way handshake completes
- TLS/SSL encryption negotiation succeeds

**Protocols Involved:**
1. DNS query (UDP/53) to resolve www.ftx.com
2. TCP handshake (SYN, SYN-ACK, ACK) on port 443
3. TLS handshake for encryption
4. HTTP request over encrypted connection

#### Test 1.3: HTTP/DNS (Unencrypted Web Traffic)

**Test Method:**
Navigate to `http://www.whynohttps.com` in web browser

**Expected Result:** ✅ Website loads successfully

**What This Validates:**
- HTTP outbound rule (port 80) is working
- System can handle both encrypted and unencrypted traffic
- Firewall correctly differentiates between HTTP and HTTPS

**Security Note:**
Modern browsers display warnings for HTTP sites. This test confirms the firewall allows HTTP, but in production environments, consider:
- Blocking HTTP entirely
- Implementing SSL/TLS inspection
- Using web filtering/proxy instead

#### Test 1.4: FTP Protocol

**Command:**
```cmd
ftp bks-speedtest-1.tele2.net
```

**Expected Result:** ✅ FTP connection established

**What This Validates:**
- FTP outbound rule (port 21) is working
- Active/Passive FTP modes function correctly
- Firewall ALG (Application Layer Gateway) handles FTP properly

**FTP Connection Process:**
1. Control connection established (port 21)
2. Authentication (username/password)
3. Data connection negotiation (port 20 or dynamic port)
4. File transfer commands available

**Common FTP Issues:**
- **Passive mode required:** Some firewalls block active mode
- **Data connection failures:** Dynamic ports not allowed
- **NAT traversal problems:** FTP embeds IP addresses in protocol

#### Test 1.5: Windows Update

**Test Method:**
Navigate to Settings → Windows Update → Check for updates

**Expected Result:** ✅ Updates check successfully, no errors

**What This Validates:**
- HTTPS traffic to Microsoft servers is allowed
- Windows Update specific endpoints are reachable
- System can download update metadata and files

**Windows Update Requirements:**
- HTTPS (443) to multiple Microsoft domains
- HTTP (80) sometimes required for metadata
- CDN access for update downloads
- Background Intelligent Transfer Service (BITS) functionality

**Enterprise Consideration:**
Direct internet access for updates can consume significant bandwidth. Consider:
- WSUS for centralized update management
- Peer-to-peer delivery (Windows 10/11 feature)
- Scheduled update windows
- Bandwidth throttling

---

### Test Suite 2: AdminNet Inbound Protocol Testing

#### Test 2.1: WinRM (Windows Remote Management)

**Command (from management workstation):**
```powershell
Test-WSMan 10.42.32.12
```

**Expected Result:** ✅ Returns WinRM service information

**What This Validates:**
- WinRM inbound rule (ports 5985/5986) is working
- Windows Remote Management service is running on target
- Network connectivity between source and destination
- No intermediate firewalls blocking traffic

**Output Interpretation:**
```xml

    http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
    Microsoft Corporation
    OS: 10.0.19045 SP: 0.0 Stack: 3.0

```

**Success Indicators:**
- XML response received
- ProductVendor shows Microsoft
- ProtocolVersion shows WS-Management schema

**Advanced WinRM Usage:**
```powershell
# Establish remote PowerShell session
Enter-PSSession -ComputerName 10.42.32.12 -Credential (Get-Credential)

# Execute remote command
Invoke-Command -ComputerName 10.42.32.12 -ScriptBlock { Get-Process }
```

#### Test 2.2: RDP (Remote Desktop Protocol)

**Test Method:**
1. Open Remote Desktop Connection (mstsc.exe)
2. Enter IP: 10.42.32.12
3. Click Connect

**Expected Result:** ✅ Credential prompt appears

**What This Validates:**
- RDP inbound rule (port 3389) is working
- RDP service is running on target (Windows 10)
- TCP connection established successfully
- No firewall blocking RDP traffic

**Connection Process:**
1. TCP handshake on port 3389
2. RDP protocol negotiation
3. TLS encryption establishment (if NLA enabled)
4. Credential prompt displayed

**Security Best Practices for RDP:**
- Enable Network Level Authentication (NLA)
- Use strong passwords or certificates
- Implement account lockout policies
- Enable RDP connection logging
- Consider RD Gateway for external access
- Use multi-factor authentication

**Common RDP Issues:**
- "Remote Desktop can't connect" - Port 3389 blocked
- "Authentication error" - NLA or certificate issues
- "User not allowed" - Remote Desktop Users group membership
- Black screen - Graphics driver or policy issues

#### Test 2.3: SSH (Secure Shell)

**Test Method:**
1. Open PuTTY
2. Enter Host Name: 10.43.32.11 (Ubuntu server)
3. Port: 22
4. Connection Type: SSH
5. Click Open

**Expected Result:** ✅ PuTTY Security Alert appears

**What This Validates:**
- SSH inbound rule (port 22) is working
- SSH service (sshd) is running on Ubuntu server
- Network connectivity established
- SSH key exchange initiated

**PuTTY Security Alert:**
```
The server's host key is not cached in the registry.
You have no guarantee that the server is the computer you think it is.
The server's ssh-ed25519 key fingerprint is:
ssh-ed25519 256 xx:xx:xx:xx:...

If you trust this host, hit Yes to add the key to PuTTY's cache.
```

**Why This Alert Appears:**
- First connection to this server
- PuTTY doesn't have the host key cached
- Security feature to prevent MITM attacks
- Should verify fingerprint matches server's actual key

**After Accepting:**
- Login prompt appears
- Enter username and password
- Successful authentication grants shell access

**SSH Security Best Practices:**
```bash
# On server side:
# 1. Disable password authentication
PasswordAuthentication no

# 2. Use SSH keys only
PubkeyAuthentication yes

# 3. Disable root login
PermitRootLogin no

# 4. Change default port
Port 2222  # Instead of 22

# 5. Limit user access
AllowUsers sysadmin adminuser

# 6. Enable key-based authentication
# Generate key pair: ssh-keygen -t ed25519
# Copy public key: ssh-copy-id user@server
```

#### Test 2.4: ICMP to Ubuntu Server

**Command:**
```cmd
ping 10.43.32.11
```

**Expected Result:** ✅ Replies received from Ubuntu server

**What This Validates:**
- Inter-VLAN routing working (AdminNet → ServerNet)
- ICMP allowed between network segments
- Ubuntu server's firewall allows ICMP (if enabled)
- No ACLs blocking cross-segment traffic

**Output Analysis:**
```
Pinging 10.43.32.11 with 32 bytes of data:
Reply from 10.43.32.11: bytes=32 time<1ms TTL=64
Reply from 10.43.32.11: bytes=32 time<1ms TTL=64
Reply from 10.43.32.11: bytes=32 time<1ms TTL=64
Reply from 10.43.32.11: bytes=32 time<1ms TTL=64

Ping statistics for 10.43.32.11:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

**Key Metrics:**
- **0% packet loss:** Stable connection
- **TTL=64:** Standard Linux/Unix TTL value
- **<1ms latency:** Local network, very fast
- **Consistent timing:** No network congestion

---

### Test Suite 3: Administrative Access Control Validation

#### Security Principle Being Tested:
**Only ONE designated device should manage the pfSense firewall.**

All other devices should be **blocked** from accessing pfSense management interfaces.

---

#### Test 3.1: OutsideDevice Access Tests (Should FAIL)

**Purpose:** Verify that OutsideDevice CANNOT access pfSense

##### Test 3.1.1: HTTP Access from OutsideDevice

**Test Method:**
Open web browser, navigate to: `http://10.42.32.1`

**Expected Result:** ❌ Connection timeout or refused

**What This Validates:**
- HTTP to pfSense is blocked from OutsideDevice
- Firewall rule correctly denies non-authorized sources
- System cannot be managed via unencrypted HTTP

**Browser Behavior:**
```
This site can't be reached
10.42.32.1 took too long to respond
ERR_CONNECTION_TIMED_OUT
```

**Security Success:** OutsideDevice cannot access pfSense web interface

##### Test 3.1.2: HTTPS Access from OutsideDevice

**Test Method:**
Open web browser, navigate to: `https://10.42.32.1`

**Expected Result:** ❌ Connection timeout or refused

**What This Validates:**
- HTTPS (port 443) to pfSense blocked from OutsideDevice
- Management interface not accessible to unauthorized devices
- Administrative control is restricted

**Why This Matters:**
If OutsideDevice could access pfSense:
- Attacker could modify firewall rules
- Network segmentation could be bypassed
- Security policies could be disabled
- Entire network security compromised

##### Test 3.1.3: SSH Access from OutsideDevice

**Command:**
```bash
ssh 10.42.32.1
```

**Expected Result:** ❌ Connection timeout or connection refused

**What This Validates:**
- SSH (port 22) to pfSense blocked from OutsideDevice
- Command-line management interface protected
- Cannot bypass web interface restrictions via SSH

**Terminal Output:**
```
ssh: connect to host 10.42.32.1 port 22: Connection timed out
```
or
```
ssh: connect to host 10.42.32.1 port 22: Connection refused
```

**Difference Between Timeout and Refused:**
- **Timeout:** Firewall silently drops packets (stealthy)
- **Refused:** Firewall sends TCP RST packet (explicit rejection)
- **Best Practice:** Use "Block" (silent drop) for security devices

---

#### Test 3.2: UbuntuClient Access Tests (Should FAIL)

**Purpose:** Verify that UbuntuClient (server) CANNOT access pfSense

##### Test 3.2.1: HTTP Access from UbuntuClient

**Test Method:**
Open Firefox, navigate to: `http://10.42.32.1`

**Expected Result:** ❌ Connection timeout or refused

**What This Validates:**
- HTTP access blocked from ServerNet to pfSense
- Server infrastructure cannot manage firewall
- Principle of separation: servers shouldn't manage network infrastructure

**Why Servers Shouldn't Manage Firewalls:**
- If server is compromised, attacker cannot modify firewall rules
- Prevents lateral movement after server breach
- Maintains clear separation of duties
- Aligns with defense-in-depth strategy

##### Test 3.2.2: HTTPS Access from UbuntuClient

**Test Method:**
Navigate to: `https://10.42.32.1`

**Expected Result:** ❌ Connection timeout or refused

**What This Validates:**
- Management interface not accessible from ServerNet
- HTTPS blocked from Ubuntu server
- Administrative boundaries enforced

##### Test 3.2.3: SSH Access from UbuntuClient

**Command:**
```bash
ssh admin@10.42.32.1
```

**Expected Result:** ❌ Connection timeout or refused

**What This Validates:**
- SSH management blocked from server network
- Command-line administration restricted
- Even using correct credentials, connection refused by firewall

**Expected Terminal Output:**
```bash
sysadmin@ubnetdef:~$ ssh admin@10.42.32.1
ssh: connect to host 10.42.32.1 port 22: Connection timed out
```

---

#### Test 3.3: Windows 10 Client Access Tests (Should SUCCEED)

**Purpose:** Verify that ONLY Windows 10 Client CAN access pfSense

##### Test 3.3.1: HTTPS Access from Win10Client

**Test Method:**
Open web browser, navigate to: `https://10.42.32.1`

**Expected Result:** ✅ pfSense login page appears

**What This Validates:**
- HTTPS rule for Win10Client → pfSense is working
- Administrative access granted to authorized device
- Web-based management available from designated workstation

**Login Page Elements:**
```
pfSense - Login
Username: [        ]
Password: [        ]
[ ] Save Password
        [Sign In]
```

**Success Indicators:**
- pfSense logo and branding visible
- Login form functional
- SSL certificate accepted (or warning for self-signed cert)
- Can proceed to authenticate with admin credentials

**After Successful Login:**
- Dashboard displays system status
- Can navigate to Firewall → Rules
- Can modify configuration
- Full administrative capabilities available

##### Test 3.3.2: SSH Access from Win10Client

**Command:**
```powershell
ssh admin@10.42.32.1
```

**Expected Result:** ✅ Password prompt appears

**What This Validates:**
- SSH rule for Win10Client → pfSense is working
- Command-line management available
- Alternative administrative method accessible

**Connection Process:**
```powershell
PS C:\> ssh admin@10.42.32.1
The authenticity of host '10.42.32.1 (10.42.32.1)' can't be established.
ECDSA key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.42.32.1' (ECDSA) to the list of known hosts.
admin@10.42.32.1's password:
```

**After Successful Authentication:**
```
*** Welcome to pfSense 2.7.2-RELEASE (amd64) on pfsense ***

 WAN (wan)       -> em0        -> v4/DHCP4: 192.168.254.x/24
 LAN (lan)       -> em1        -> v4: 10.42.32.1/24
 OPT1 (opt1)     -> em2        -> v4: 10.43.32.1/24

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart webConfigurator
 3) Reset webConfigurator password    12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Disable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

Enter an option:
```

**CLI Management Capabilities:**
- All pfSense functions available
- Can modify configuration via command-line
- Useful for automation and scripting
- Alternative when web interface unavailable

---

### Test Results Summary

| Test Category | Test Description | Source | Expected | Result |
|--------------|------------------|--------|----------|--------|
| **Outbound Protocols** | ICMP (ping 8.8.8.8) | Win10 | ✅ Success | ✅ Pass |
| | HTTPS (ftx.com) | Win10 | ✅ Success | ✅ Pass |
| | HTTP (whynohttps.com) | Win10 | ✅ Success | ✅ Pass |
| | FTP (tele2.net) | Win10 | ✅ Success | ✅ Pass |
| | Windows Update | Win10 | ✅ Success | ✅ Pass |
| **Inbound Protocols** | WinRM Test | Outside → Win10 | ✅ Success | ✅ Pass |
| | RDP Connection | Outside → Win10 | ✅ Success | ✅ Pass |
| | SSH via PuTTY | Outside → Ubuntu | ✅ Success | ✅ Pass |
| | ICMP ping | Win10 → Ubuntu | ✅ Success | ✅ Pass |
| **Access Control** | HTTP to pfSense | OutsideDevice | ❌ Blocked | ✅ Pass |
| | HTTPS to pfSense | OutsideDevice | ❌ Blocked | ✅ Pass |
| | SSH to pfSense | OutsideDevice | ❌ Blocked | ✅ Pass |
| | HTTP to pfSense | UbuntuClient | ❌ Blocked | ✅ Pass |
| | HTTPS to pfSense | UbuntuClient | ❌ Blocked | ✅ Pass |
| | SSH to pfSense | UbuntuClient | ❌ Blocked | ✅ Pass |
| | HTTPS to pfSense | Win10Client | ✅ Allowed | ✅ Pass |
| | SSH to pfSense | Win10Client | ✅ Allowed | ✅ Pass |

**Overall Test Results: 17/17 Passed (100% Success Rate)**

---

## 📊 Firewall Policy Documentation

### Professional Security Memo

As part of this lab, I created a professional security policy memo proposing firewall rule changes to the CEO. This demonstrates:

**Business Communication Skills:**
- Professional memo formatting
- Clear executive summary
- Technical details in accessible language
- Action-oriented recommendations

**Security Policy Development:**
- Analyzed existing firewall rules
- Identified security improvements
- Proposed new rule set
- Justified changes with business impact

### Proposed Firewall Rules (From Memo)

| Rule | Protocol | Source | S.Port | Destination | D.Port | Gateway | Action |
|------|----------|--------|--------|-------------|--------|---------|--------|
| 1 | IPv4 TCP | * | * | 173.23.0.12 | 80 | * | Allow |
| 2 | IPv4 TCP | * | * | 173.23.0.12 | 443 | * | Allow |
| 3 | IPv4 UDP | * | * | 172.23.0.12 | 8080 | * | Allow |
| 4 | IPv4 UDP | * | * | 172.23.0.1 | 3306 | * | Allow |
| 5 | IPv4 TCP | * | * | * | 3306 | * | **Disallow** |
| 6 | IPv4 TCP | * | * | * | 1234 | * | **Disallow** |
| 7 | IPv4 TCP | * | * | * | * | * | Allow |
| 8 | IPv4 TCP | * | * | 172.23.0.68 | 119 | * | Allow |
| 9 | IPv4 TCP | 123.165.151.32 | * | 172.23.0.77 | 22 | * | Allow |
| 10 | IPv4 TCP/UDP | * | * | 172.23.0.8 | 189 | * | Allow |
| 11 | IPv4 TCP | 173.74.82.94 | * | 172.23.0.50 | 5432 | * | Allow |
| 12 | IPv4 UDP | 172.23.0.12 | * | * | 123 | * | Allow |
| 13 | IPv4 TCP | * | * | 172.23.0.12 | 80 | * | Allow |
| 14 | IPv4 TCP | * | * | 172.23.0.12 | 443 | * | Allow |

### Rule Analysis & Justification

**Rule 1-2: Web Server Access (HTTP/HTTPS)**
- Allows public access to web server at 172.23.0.12
- Standard ports 80/443 for web services
- Essential for business operations

**Rule 3: Alternative Web Service**
- UDP port 8080 to same server
- Likely custom application or API
- May be WebSocket or streaming protocol

**Rule 4: MySQL Database Access**
- UDP to port 3306 (MySQL typically uses TCP, unusual)
- Allowed to gateway/router (172.23.0.1)
- Possible MySQL Cluster or NDB usage

**Rule 5-6: Security Restrictions**
- **Rule 5:** Block MySQL (3306) from all other sources
- **Rule 6:** Block port 1234 (prevent unauthorized service)
- Implements principle of least privilege

**Rule 7: Catch-All Allow Rule**
- **WARNING:** Very permissive rule
- Allows all TCP traffic after specific denies
- Should be last resort, consider removing in production
- Better to explicitly allow needed protocols

**Rule 8: NNTP Access**
- Port 119 (Network News Transfer Protocol)
- Legacy protocol for Usenet newsgroups
- Specific destination: 172.23.0.68

**Rule 9: SSH from Specific Source**
- SSH (port 22) from single IP (123.165.151.32)
- Destination: 172.23.0.77
- Excellent security practice: source IP restriction

**Rule 10: Custom Application**
- Port 189 (unknown/custom application)
- Both TCP and UDP allowed
- Specific destination: 172.23.0.8

**Rule 11: PostgreSQL from Specific Source**
- Port 5432 (PostgreSQL database)
- Source-restricted: 173.74.82.94
- Destination: 172.23.0.50
- Best practice for database security

**Rule 12: NTP Traffic**
- UDP port 123 (Network Time Protocol)
- Time synchronization for 172.23.0.12
- Critical for logging and authentication

**Rules 13-14: Duplicate Web Server Rules**
- Same as Rules 1-2
- Redundant - should be removed
- May indicate configuration error or testing artifact

### Security Recommendations

**Improvements Needed:**
1. **Remove Rule 7:** Replace catch-all with specific allow rules
2. **Consolidate Rules 1/13 and 2/14:** Remove duplicates
3. **Add Logging:** Enable logging on all deny rules
4. **Review Rule 3:** Verify if UDP 8080 is actually required
5. **Document Rule 4:** Clarify why MySQL uses UDP
6. **Add Rate Limiting:** Prevent DoS attacks on public services

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Firewall Rule Configuration**
   - Created protocol-specific inbound rules (WinRM, RDP, SSH)
   - Configured outbound rules for business functions (FTP, HTTP, DNS)
   - Implemented deny rules for security hardening
   - Understood rule evaluation order and precedence

2. **Access Control Implementation**
   - Applied principle of least privilege
   - Restricted administrative access to single workstation
   - Disabled overly permissive default rules
   - Created explicit allow/deny policies

3. **Protocol Understanding**
   - Demonstrated knowledge of Layer 4 (TCP/UDP) protocols
   - Understood application layer protocols (HTTP, FTP, SSH, RDP)
   - Configured port-based filtering correctly
   - Recognized protocol-specific firewall challenges (FTP ALG)

4. **Systematic Testing**
   - Created comprehensive test plan
   - Validated both positive (should work) and negative (should fail) cases
   - Documented all test results with screenshots
   - Proved firewall rules work as intended

5. **Security Documentation**
   - Wrote professional security policy memo
   - Created firewall rule tables with justifications
   - Documented network topology changes
   - Provided evidence-based recommendations

### Cybersecurity Principles Applied

**Defense in Depth:**
- Multiple security layers (network segmentation + firewall rules)
- Administrative access controls
- Protocol-specific restrictions

**Least Privilege:**
- Only required protocols allowed
- Source/destination IP restrictions where possible
- Single management workstation designated

**Default Deny:**
- Implicit deny policy (only explicitly allowed traffic passes)
- Explicit deny rules for sensitive services
- Administrative interfaces heavily restricted

**Auditing & Accountability:**
- All rules documented with descriptions
- Test results recorded
- Professional memo for change management

---

## 🔐 Security Implications & Real-World Impact

### Attack Vectors Mitigated

**1. Unauthorized Remote Access**
- **Threat:** Attacker attempts RDP/SSH brute force
- **Mitigation:** Source IP restrictions limit exposure
- **Result:** Only specific management IPs can attempt authentication

**2. Firewall Management Compromise**
- **Threat:** Attacker gains access to any AdminNet device and attempts to access pfSense
- **Mitigation:** Only Win10Client can manage pfSense
- **Result:** Compromising other devices doesn't grant firewall access

**3. Lateral Movement**
- **Threat:** Attacker compromises one network segment and pivots to others
- **Mitigation:** Firewall rules control inter-segment traffic
- **Result:** Limited ability to move between AdminNet and ServerNet

**4. Data Exfiltration**
- **Threat:** Malware attempts to exfiltrate data via unauthorized protocols
- **Mitigation:** Only approved outbound protocols allowed
- **Result:** Attacker cannot use arbitrary ports for command & control

**5. Service Exploitation**
- **Threat:** Attacker scans for and exploits vulnerable services
- **Mitigation:** Inbound rules limit exposed services
- **Result:** Reduced attack surface, fewer exploitable services

### Compliance & Governance

**Regulatory Requirements Met:**

**PCI-DSS (Payment Card Industry):**
- Requirement 1.2.1: Restrict inbound and outbound traffic
- Requirement 1.3: Prohibit direct public access to servers
- Requirement 2.2.2: Enable only necessary services

**HIPAA (Healthcare):**
- Technical Safeguard: Access controls
- Transmission Security: Encrypt health data (HTTPS required)
- Audit Controls: Firewall logging enabled

**NIST Cybersecurity Framework:**
- PR.AC-5: Network integrity protected
- PR.PT-3: Least functionality principle
- DE.CM-1: Network monitored

**SOX (Sarbanes-Oxley):**
- Change management: Documented firewall changes
- Access controls: Administrative restriction
- Audit trail: Professional memo and testing documentation

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Network Security Engineer:**
- Design and implement firewall policies
- Configure enterprise-grade firewalls (pfSense, Palo Alto, Fortinet)
- Create and maintain firewall rule documentation
- Perform regular rule reviews and audits

**Security Operations Center (SOC) Analyst:**
- Investigate firewall alerts and blocks
- Analyze traffic patterns for anomalies
- Recommend firewall rule adjustments
- Monitor for policy violations

**System Administrator:**
- Manage remote access solutions (RDP, SSH, WinRM)
- Configure outbound access for system updates
- Balance security requirements with business needs
- Troubleshoot connectivity issues

**Compliance Analyst:**
- Document security controls for audits
- Verify firewall configurations meet regulations
- Create security policy documentation
- Maintain evidence for compliance frameworks

**Penetration Tester:**
- Understand firewall rules to identify weaknesses
- Test firewall effectiveness during engagements
- Recommend security improvements
- Validate rule implementation

### Enterprise Scenarios

**Scenario 1: Remote Work Infrastructure**
```
Challenge: Enable secure remote access during COVID-19 pandemic
Solution Applied:
- Configured VPN access through pfSense
- Implemented RDP/SSH rules for remote administration
- Source IP restrictions for VPN endpoints
- MFA integration for administrative access
```

**Scenario 2: PCI-DSS Compliance**
```
Challenge: Segment payment card processing environment
Solution Applied:
- Created separate VLAN for PCI systems (like ServerNet)
- Firewall rules restrict access to cardholder data
- Only approved workstations can access PCI segment
- All traffic logged and monitored
```

**Scenario 3: Incident Response**
```
Challenge: Ransomware outbreak in organization
Solution Applied:
- Quickly created deny rules to block C2 communications
- Isolated infected segments using firewall rules
- Prevented lateral movement between VLANs
- Restored connectivity for critical business services only
```

---

## 📚 Commands & Tools Reference

### pfSense Web Configurator Navigation

```
Firewall → Rules → [Interface] → Add (↑ button)
  ↓
Configure Rule:
  - Action: Pass/Block/Reject
  - Interface: External/AdminNet/ServerNet
  - Protocol: TCP/UDP/ICMP/Any
  - Source: Network/Address/Any
  - Destination: Network/Address/Any
  - Port Range: Specific or Custom
  - Description: Rule purpose
  ↓
Save → Apply Changes
```

### Testing Commands

**Windows PowerShell:**
```powershell
# WinRM testing
Test-WSMan 
Enter-PSSession -ComputerName  -Credential (Get-Credential)

# Network connectivity
ping 
Test-NetConnection  -Port 

# DNS resolution
Resolve-DnsName 
nslookup 

# FTP testing
ftp 

# SSH from Windows
ssh @
```

**Linux/Ubuntu:**
```bash
# Connectivity testing
ping 
nc -zv    # Port scanning

# SSH testing
ssh @

# Web testing
curl http://example.com
wget https://example.com

# FTP testing
ftp 
```

**Remote Desktop:**
```
mstsc.exe  # Launch Remote Desktop Connection
mstsc /v:<ip_address>  # Connect directly
```

---

## 🎯 Advanced Topics & Next Steps

### Firewall Rule Optimization

**Current State:** Rules listed sequentially, evaluated top-to-bottom

**Optimization Strategies:**
1. **Most-Used Rules First:** Place high-traffic rules at top for performance
2. **Deny Rules Early:** Block unwanted traffic before processing allows
3. **Specific Before Generic:** Specific rules before broad rules
4. **Disable Unused Rules:** Temporarily disable instead of delete for rollback
5. **Use Aliases:** Group IPs/ports into aliases for easier management

### Advanced Security Features

**Next Lab Topics:**

**1. IPS Mode (Intrusion Prevention)**
- Configure Suricata in inline mode
- Automatically block malicious traffic
- Balance security vs false positives

**2. VPN Implementation**
- OpenVPN for remote access
- Site-to-site VPN for branch offices
- Always-on VPN for mobile devices

**3. Web Application Firewall (WAF)**
- Install HAProxy with ModSecurity
- Protect web applications from OWASP Top 10
- SQL injection and XSS prevention

**4. Advanced Threat Protection**
- pfBlockerNG for IP/DNS blacklisting
- GeoIP blocking (block entire countries)
- Threat intelligence feed integration

**5. Traffic Shaping (QoS)**
- Prioritize VoIP and video conferencing
- Limit bandwidth for non-business traffic
- Guarantee bandwidth for critical applications

**6. High Availability**
- CARP (Common Address Redundancy Protocol)
- Automatic failover between firewall pairs
- Zero-downtime network protection

---

## 💡 Lessons Learned

### Technical Insights

1. **Rule Order Matters:** First matching rule wins, order strategically
2. **Test Before Production:** Always test firewall changes in lab first
3. **Document Everything:** Future administrators (and future you) will thank you
4. **Least Privilege is Hard:** Balancing security and usability requires iteration
5. **Default Deny is Essential:** Better to explicitly allow than implicitly allow

### Professional Practices

1. **Change Management:** Document all changes with business justification
2. **Testing is Critical:** Never assume rules work, always validate
3. **Communication Skills:** Technical skills must be communicated to non-technical stakeholders
4. **Evidence-Based:** Screenshots and logs prove compliance and due diligence
5. **Continuous Improvement:** Regular firewall audits identify obsolete rules

### Security Mindset

1. **Think Like an Attacker:** What would you do if you compromised one system?
2. **Defense in Depth:** Firewall is one layer, not the only layer
3. **Assume Breach:** Design rules assuming internal compromise
4. **Monitor and Alert:** Rules without logging provide no visibility
5. **Regular Reviews:** Security requirements change, rules must evolve

---

## 🔗 Related Skills & Technologies

### Complementary Firewall Technologies

**Next-Generation Firewalls (NGFW):**
- **Palo Alto Networks:** Application-aware firewall with threat intelligence
- **Fortinet FortiGate:** Unified threat management with SD-WAN
- **Cisco Firepower:** Integration with Cisco ecosystem
- **Check Point:** Enterprise-grade firewall with sandboxing

**Cloud Firewalls:**
- **AWS Security Groups:** Virtual firewall for EC2 instances
- **Azure Network Security Groups:** Network-level firewall in Azure
- **GCP Firewall Rules:** VPC firewall in Google Cloud
- **Cloudflare Magic Firewall:** Network-layer DDoS protection

**Web Application Firewalls:**
- **ModSecurity:** Open-source WAF engine
- **AWS WAF:** Cloud-native web application firewall
- **Cloudflare WAF:** CDN-integrated application protection
- **Imperva:** Enterprise WAF with bot protection

### Industry Certifications

**Firewall-Specific:**
- **Palo Alto PCNSA/PCNSE:** Palo Alto Networks Certified Network Security Administrator/Engineer
- **Fortinet NSE:** Network Security Expert certification levels
- **Check Point CCSA/CCSE:** Check Point Certified Security Administrator/Expert
- **Cisco CCNP Security:** Advanced Cisco firewall and VPN

**General Security:**
- **CompTIA Security+:** Includes firewall and network security
- **CISSP:** Domain 4 covers network security
- **GIAC GCIA:** Intrusion detection and firewall analysis
- **SANS SEC503:** Intrusion Detection and Network Forensics

---

## 📸 Lab Evidence

All screenshots demonstrating successful completion are documented in the original lab report, including:

**Firewall Configuration:**
- ✅ WinRM inbound rule configuration
- ✅ FTP outbound rule configuration  
- ✅ Anti-lockout rule modification
- ✅ Management access restriction rules
- ✅ Complete rule sets for all interfaces (External, AdminNet, ServerNet)

**Testing & Validation:**
- ✅ ICMP/ping tests
- ✅ HTTP and HTTPS web browsing
- ✅ FTP connection establishment
- ✅ Windows Update functionality
- ✅ WinRM connectivity test
- ✅ RDP connection prompt
- ✅ PuTTY SSH security alert
- ✅ Successful pfSense access from Win10Client
- ✅ Blocked access from OutsideDevice and UbuntuClient

**Documentation:**
- ✅ Updated network topology diagram
- ✅ Professional security policy memo
- ✅ Firewall rule table with justifications

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**All Tests Passed:** ✅ 17/17 (100%)  
**Firewall Rules Implemented:** ✅ 10+ rules across 3 interfaces  
**Access Control:** ✅ Administrative access properly restricted  
**Documentation:** ✅ Complete with professional memo and topology

---

## 🔍 Troubleshooting Guide

### Common Issues & Solutions

**Issue 1: Rule Not Working**
```
Symptoms: Traffic still blocked/allowed despite rule
Diagnosis:
  1. Check rule order (higher rules evaluated first)
  2. Verify rule is enabled (not disabled)
  3. Check states table (old connections cached)
  4. Verify interface is correct
Solution:
  - Move rule higher in list if needed
  - Diagnostics → States → Reset States
  - Clear browser cache for web tests
```

**Issue 2: Locked Out of pfSense**
```
Symptoms: Cannot access pfSense web interface
Diagnosis:
  1. Disabled anti-lockout before creating replacement rule
  2. Management rule has wrong source IP
  3. Firewall rule syntax error
Solution:
  - Connect to pfSense console (direct access)
  - Option 8: Shell
  - pfctl -d (disable firewall temporarily)
  - Fix rules via web interface
  - pfctl -e (re-enable firewall)
```

**Issue 3: Outbound Traffic Blocked**
```
Symptoms: Cannot browse internet, updates fail
Diagnosis:
  1. Missing outbound allow rules
  2. NAT not configured properly
  3. DNS not working
Solution:
  - Firewall → Rules → Add outbound rules
  - Firewall → NAT → Outbound → Check mode
  - Diagnostics → Ping → Test from pfSense
```

**Issue 4: WinRM Test Fails**
```
Symptoms: Test-WSMan returns error
Diagnosis:
  1. WinRM service not running on target
  2. Firewall rule incorrect
  3. Windows Firewall blocking
Solution:
  - Enable-PSRemoting on target
  - Check pfSense rule (ports 5985/5986)
  - Check Windows Firewall on target
```

---

