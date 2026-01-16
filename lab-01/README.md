# Lab 01: Operating System Installation & Network Connectivity Analysis

## 📋 Lab Overview  
**Difficulty Level:** Beginner/Intermediate

### Objective
This lab demonstrates foundational system administration skills by installing two different operating systems (Windows 10 and Ubuntu Linux) in a virtualized environment and validating network connectivity using command-line interface (CLI) tools. The lab establishes a baseline understanding of cross-platform system configuration and network diagnostics.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Virtualization Management:** Installing and configuring multiple operating systems in VMware vSphere environment
- **Windows Administration:** Installing Windows 10 Enterprise LTSC and configuring basic security settings
- **Linux Administration:** Installing Ubuntu Linux with proper hostname configuration and package management
- **Network Diagnostics:** Using platform-specific CLI tools to verify network connectivity and troubleshoot issues
- **Cross-Platform Knowledge:** Understanding differences between Windows and Linux networking commands
- **Documentation:** Creating network topology diagrams and documenting system configurations

---

## 🛠️ Tools & Technologies Used

### Virtualization Platform
- **VMware vSphere/vCenter** - Enterprise virtualization platform for VM management
- **VMware Tools / Open VM Tools** - Guest OS optimization and integration tools

### Operating Systems
- **Windows 10 Enterprise LTSC Evaluation** - Long-Term Servicing Channel for stable enterprise deployments
- **Ubuntu Linux (Desktop)** - Popular Debian-based Linux distribution

### Command-Line Tools
| Tool | Platform | Purpose |
|------|----------|---------|
| `ipconfig` | Windows | Display network adapter configuration |
| `ip route` (ip r) | Linux | View and manipulate routing tables |
| `ping` | Both | Test network connectivity and measure latency |
| PowerShell | Windows | Advanced command-line shell and scripting environment |
| Terminal | Linux | Command-line interface for system administration |

---

## 🔧 Lab Environment Setup

### Network Configuration
- **Network Subnet:** 192.168.0.0/20 (supports 4,096 host addresses)
- **Default Gateway:** 192.168.0.1
- **DNS Server:** 8.8.8.8 (Google Public DNS)
- **Ubuntu Client IP:** 192.168.13.49
- **Windows Client IP:** 192.168.15.109

### System Credentials
- **Username:** sysadmin
- **Password:** Change.me!
- **Ubuntu Hostname:** ubnetdef[XX] (where XX = team ID)

---

## 📝 Methodology & Implementation

### Part 1: Windows 10 Installation

#### Installation Steps
1. **ISO Mounting:** Mounted `F24SysSecWindows.iso` to virtual machine
2. **Edition Selection:** Selected Windows 10 Enterprise LTSC Evaluation for long-term stability
3. **Installation Type:** Custom installation (clean install)
4. **Disk Configuration:** Utilized default disk partitioning scheme
5. **System Restarts:** Allowed multiple automatic restarts during setup
6. **Account Configuration:**
   - Bypassed Microsoft account requirement using "Domain join instead"
   - Created local administrator account: `sysadmin`
   - Configured three security questions for account recovery
7. **Privacy Settings:** Disabled all telemetry and data collection options for security
8. **VMware Tools:** Installed VMware Tools for enhanced performance and integration

#### Security Considerations
- Used Enterprise LTSC to avoid consumer-grade telemetry
- Disabled unnecessary privacy-invasive features during installation
- Created strong password following enterprise password policies

### Part 2: Ubuntu Linux Installation

#### Installation Steps
1. **Installation Mode:** Selected "Install Ubuntu" (full installation)
2. **Software Selection:** Normal installation with updates downloaded during setup
3. **Disk Configuration:** "Erase disk and install Ubuntu" (clean installation)
4. **System Configuration:**
   - Username: `sysadmin`
   - Hostname: `ubnetdef[XX]` (standardized naming convention)
   - Password: `Change.me!`
5. **System Updates:**
   - Ran Software Updater application post-installation
   - Executed multiple update cycles until system was fully patched
   - Rebooted between update cycles for kernel updates
6. **VM Integration:** Installed Open VM Tools for VMware integration
   ```bash
   sudo apt install open-vm-tools-desktop
   ```

#### Why Open VM Tools?
Open VM Tools is the open-source implementation of VMware Tools, providing:
- Better mouse and keyboard integration
- Shared folders capability
- Improved graphics performance
- Time synchronization with host

---

## 🔍 Network Connectivity Testing

### Windows Network Diagnostics

#### 1. Network Configuration Discovery
**Command:** `ipconfig`

**Purpose:** Displays all network adapter configurations including IP address, subnet mask, and default gateway.

**Key Information Obtained:**
- **IP Address:** 192.168.15.109 (dynamically assigned or static)
- **Subnet Mask:** 255.255.240.0 (/20 CIDR notation)
- **Default Gateway:** 192.168.0.1 (router interface)

**Why This Matters:** Understanding your network configuration is the first step in troubleshooting connectivity issues. The `/20` subnet provides a large address space suitable for enterprise networks.

#### 2. Internet Connectivity Test - IP Address
**Command:** `ping 8.8.8.8`

**Purpose:** Tests Layer 3 (Network Layer) connectivity to Google's public DNS server.

**What Success Indicates:**
- ✅ Physical/Virtual network adapter is functioning
- ✅ IP stack is properly configured
- ✅ Default gateway is reachable and routing correctly
- ✅ Firewall rules allow ICMP traffic
- ✅ Internet connectivity is established

**Metrics Analyzed:**
- **Reply time (latency):** Measures round-trip time to destination
- **TTL (Time To Live):** Shows number of hops remaining (helps identify network distance)
- **Packet loss:** 0% loss indicates stable connection

#### 3. DNS Resolution Test
**Command:** `ping dns.google`

**Purpose:** Tests both DNS resolution AND network connectivity.

**Two-Phase Test:**
1. **DNS Resolution:** System queries DNS server to resolve `dns.google` → `8.8.8.8`
2. **Connectivity Test:** Pings the resolved IP address

**Why This Is Important:** If `ping 8.8.8.8` works but `ping dns.google` fails, it indicates a DNS configuration problem rather than network connectivity issue. This is a critical troubleshooting technique.

---

### Linux Network Diagnostics

#### 1. Routing Table Analysis
**Command:** `ip r` (short for `ip route`)

**Purpose:** Displays the kernel routing table, showing how packets are routed to different networks.

**Key Information Obtained:**
- **Default route:** Path to internet (via default gateway)
- **Local network routes:** Direct connections to local subnet
- **Network interfaces:** Which adapter handles which network

**Sample Output Interpretation:**
```
default via 192.168.0.1 dev ens33
192.168.0.0/20 dev ens33 proto kernel scope link src 192.168.13.49
```
- First line: All non-local traffic goes through 192.168.0.1
- Second line: Traffic to 192.168.0.0/20 subnet is handled directly by ens33 interface

**Professional Skill:** Understanding routing is essential for network troubleshooting and security analysis. Misconfigurated routes can lead to connectivity issues or security vulnerabilities.

#### 2. Internet Connectivity Test - IP Address
**Command:** `ping 8.8.8.8`

**Linux Behavior Difference:** Unlike Windows (which sends 4 packets by default), Linux ping runs continuously until manually stopped with `Ctrl+C`.

**Why Continuous Ping Is Useful:**
- Monitor real-time network performance
- Detect intermittent connectivity issues
- Measure network stability over time
- Identify patterns in latency fluctuations

**To limit packets:** `ping -c 4 8.8.8.8` (sends only 4 packets)

#### 3. DNS Resolution Test
**Command:** `ping dns.google`

**Same Purpose as Windows:** Validates both DNS functionality and network connectivity.

**Cross-Platform Consistency:** Both operating systems can reach the same external resources, demonstrating proper network configuration on both platforms.

---

## 📊 Network Topology Analysis

### Topology Components

```
                    [Internet]
                        |
                [Router: 192.168.0.1/20]
                        |
            -------------------------
            |                       |
    [Ubuntu Client]         [Windows Client]
    192.168.13.49          192.168.15.109
```

### Component Breakdown

#### 1. **Internet Connectivity**
- External network access provided through the central router
- Enables clients to reach public resources (Google DNS, websites, etc.)

#### 2. **Router (Gateway)**
- **IP Address:** 192.168.0.1
- **Subnet:** /20 (255.255.240.0) - Supports 4,094 usable host addresses
- **Function:** 
  - Routes traffic between internal network and internet
  - Performs NAT (Network Address Translation)
  - Acts as default gateway for all clients

#### 3. **Client Devices**
- **Ubuntu Client:** 192.168.13.49
- **Windows Client:** 192.168.15.109
- Both on same /20 subnet, can communicate directly
- Both use router as default gateway for internet access

### Network Design Considerations

**Subnet Size:** The /20 network (192.168.0.0 - 192.168.15.255) provides 4,096 total addresses, suitable for:
- Small to medium enterprise networks
- Lab environments with multiple VMs
- Future expansion without re-addressing

**IP Allocation:** Both clients are in the 192.168.13.x - 192.168.15.x range, suggesting DHCP or systematic static assignment.

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Operating System Deployment**
   - Successfully installed and configured enterprise-grade Windows and Linux systems
   - Understood installation options and their security implications
   - Configured appropriate privacy and security settings

2. **Virtual Environment Management**
   - Worked with VMware vSphere/vCenter enterprise virtualization
   - Installed and configured guest tools for optimal performance
   - Managed multiple VMs in a networked environment

3. **Network Configuration & Troubleshooting**
   - Validated network connectivity using multiple methods
   - Understood the difference between Layer 3 connectivity and DNS resolution
   - Interpreted network configuration data from different platforms

4. **Cross-Platform Proficiency**
   - Demonstrated ability to work in both Windows and Linux environments
   - Understood platform-specific commands and their equivalents
   - Applied consistent troubleshooting methodology across platforms

### Cybersecurity Relevance

1. **Defense in Depth:** Understanding OS installation allows for hardening systems from the ground up
2. **Network Security:** Routing knowledge is essential for firewall configuration and network segmentation
3. **Incident Response:** Network diagnostic skills are critical for investigating security incidents
4. **Penetration Testing:** Knowledge of both Windows and Linux is required for comprehensive security testing

---

## 🔐 Security Implications

### Privacy Configuration
- Disabled Windows telemetry during installation
- Used local accounts instead of cloud-connected Microsoft accounts
- Demonstrates awareness of data privacy concerns

### Network Security Awareness
- Understanding routing tables helps identify unauthorized routes (potential backdoors)
- DNS testing validates that DNS isn't being hijacked
- Network topology documentation is essential for security auditing

### Credential Management
- Used consistent credentials across systems for lab environment
- In production: Would implement password rotation and unique credentials per system
- Demonstrates understanding of credential management principles

---

## 🚀 Real-World Applications

### IT Operations
- **System Deployment:** Skills directly applicable to enterprise desktop/server deployment
- **Help Desk:** Network troubleshooting skills essential for user support
- **System Administration:** Foundation for managing heterogeneous environments

### Cybersecurity
- **Security Operations:** Network diagnostics crucial for investigating security events
- **Malware Analysis:** Need isolated VMs with controlled network access
- **Penetration Testing:** Must understand network routing to navigate target environments
- **Digital Forensics:** Network configuration analysis helps reconstruct incident timelines

### Cloud & DevOps
- **Infrastructure as Code:** Understanding base OS installation translates to automated deployments
- **Container Environments:** Linux CLI skills directly applicable to Docker/Kubernetes
- **Hybrid Cloud:** Managing both Windows and Linux across on-prem and cloud

---

## 📚 Commands Reference

### Windows Commands
```powershell
ipconfig                    # Display network configuration
ipconfig /all              # Display detailed network information
ping <target>              # Test connectivity to target
ping -t <target>           # Continuous ping (like Linux default)
tracert <target>           # Trace route to target
nslookup <domain>          # Query DNS servers
```

### Linux Commands
```bash
ip r                       # Display routing table
ip a                       # Display all network interfaces
ping <target>              # Test connectivity (continuous by default)
ping -c 4 <target>         # Ping with packet count limit
traceroute <target>        # Trace route to target
dig <domain>               # DNS lookup utility
nslookup <domain>          # Query DNS servers
```

---

## 🎯 Next Steps & Future Labs

This foundational lab sets the stage for more advanced topics:

1. **Network Hardening:** Configuring firewalls (Windows Defender Firewall, UFW/iptables)
2. **Service Configuration:** Setting up web servers, SSH, Active Directory
3. **Security Monitoring:** Installing and configuring SIEM tools
4. **Vulnerability Assessment:** Running security scanners against configured systems
5. **Incident Response:** Simulating and responding to security incidents

---

## 📸 Lab Evidence

All screenshots demonstrating successful completion are documented in the original lab report, including:
- ✅ Windows 10 installation and desktop
- ✅ Ubuntu Linux installation and desktop  
- ✅ Windows CLI tools (CMD and PowerShell)
- ✅ Network connectivity tests (both platforms)
- ✅ Network topology diagram

---

## 💡 Lessons Learned

1. **Platform Differences Matter:** Same goal (ping test) requires different understanding of default behavior
2. **Documentation is Critical:** Network diagrams and configuration records are essential for troubleshooting
3. **Layered Troubleshooting:** Testing both IP connectivity and DNS separately helps isolate issues
4. **Foundation is Everything:** Proper installation and configuration prevents future security and stability issues

---

## 🔗 Related Skills

- Virtual Machine Management
- Windows Server Administration
- Linux System Administration  
- TCP/IP Networking
- Network Troubleshooting
- Security Baseline Configuration
- Technical Documentation

---

