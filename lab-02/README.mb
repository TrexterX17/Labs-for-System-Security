Lab 02: pfSense Router Configuration & Network Segmentation
📋 Lab Overview
Difficulty Level: Intermediate
Objective
This lab demonstrates advanced network infrastructure skills by deploying and configuring a pfSense firewall/router to create segmented networks, establishing proper routing between network segments, and implementing an Intrusion Detection System (IDS) using Suricata. This lab simulates enterprise network architecture with multiple security zones.

🎯 Learning Outcomes
By completing this lab, I demonstrated proficiency in:

Enterprise Firewall Deployment: Installing and configuring pfSense as a network gateway
Network Segmentation: Creating isolated network zones (AdminNet, ServerNet) for security
Advanced CLI Configuration: Modifying network settings using PowerShell and netplan
Routing Configuration: Establishing connectivity between multiple network segments
IDS Implementation: Deploying Suricata for network intrusion detection
Network Architecture Design: Planning and documenting multi-tier network topology
Web-Based Administration: Managing network infrastructure through GUI interfaces


🛠️ Tools & Technologies Used
Network Infrastructure

pfSense CE 2.7.2 - Open-source firewall/router platform based on FreeBSD
VMware vSphere - Enterprise virtualization platform for network infrastructure
Open-VM-Tools - Guest operating system optimization for pfSense

Security Tools

Suricata IDS/IPS - Open-source intrusion detection and prevention system
pfSense Package Manager - Built-in package management for additional functionality

Command-Line Tools
ToolPlatformPurposePowerShellWindowsAdvanced network configuration scriptingGet-NetAdapterWindowsNetwork interface enumerationNew-NetIPAddressWindowsStatic IP configurationSet-DnsClientServerAddressWindowsDNS server configurationnetplanLinuxNetwork configuration management (Ubuntu 18.04+)ip route (ip r)LinuxRouting table managementpingBothNetwork connectivity testingpfctlpfSensePacket filter control (firewall management)
Network Testing

ping - ICMP connectivity testing across network segments
ipconfig/ip - Network interface configuration verification
whatismyipaddress.com - External IP verification


🔧 Lab Environment Architecture
Network Segmentation Design
                         [Internet]
                              |
                    [External Interface]
                              |
                    [pfSense Router]
                    /              \
          [AdminNet]              [ServerNet]
          10.42.32.0/24           10.43.32.0/24
                |                      |
          [Windows 10]            [Ubuntu Linux]
          10.42.32.12             10.43.32.11
Network Specifications
Network SegmentInterfaceSubnetGatewayPurposeExternalem0Dynamic (ISP)192.168.254.254Internet connectivityAdminNetem1 (LAN)10.42.32.0/2410.42.32.1Administrative workstationsServerNetem2 (OPT1)10.43.32.0/2410.43.32.1Server infrastructure
Client Configuration
Windows 10 Client (AdminNet):

IP Address: 10.42.32.12/24
Gateway: 10.42.32.1 (pfSense AdminNet interface)
DNS Servers: 8.8.8.8, 8.8.4.4 (Google Public DNS)

Ubuntu Linux Client (ServerNet):

IP Address: 10.43.32.11/24
Gateway: 10.43.32.1 (pfSense ServerNet interface)
DNS Servers: 8.8.8.8, 8.8.4.4 (Google Public DNS)


📝 Methodology & Implementation
Phase 1: pfSense Router Installation & Configuration
1.1 Initial Installation
Process:

Mounted pfSense ISO (pfSense-CE-2.7.2-RELEASE-amd.iso) to virtual machine
Booted from ISO and followed installation wizard
Configured basic network interfaces during installation
Set initial admin credentials (admin/pfsense)

Why pfSense?

Industry-standard open-source firewall used in enterprise environments
Provides routing, firewalling, VPN, and IDS/IPS capabilities
Web-based management interface for easier administration
Extensive package ecosystem for additional functionality

1.2 Open-VM-Tools Installation
Commands Executed:
bash# At pfSense console
13  # Update from Console
8   # Shell access
pkg install pfSense-pkg-Open-VM-Tools
service -l | grep vmware  # Verify 4 vmware services
Purpose of Open-VM-Tools:

Enhanced VM performance and resource management
Better time synchronization with host
Improved graphics and mouse integration
Enables VM snapshot capabilities

Verification: Successfully identified 4 VMware services running:

vmware-guestd
vmware-kmod
vmtoolsd
vmware-host-connector

1.3 Firewall Configuration
Critical Step: Disabled pfSense firewall during initial configuration
bashpfctl -d  # Disable packet filter
Why Disable Firewall Initially?

Allows unrestricted connectivity for testing and configuration
Prevents firewall rules from blocking legitimate configuration traffic
Simplifies troubleshooting during setup phase
Production Note: Firewall should be re-enabled after configuration is complete


Phase 2: Network Migration - Windows Client to AdminNet
Windows Network Reconfiguration Process
Step 1: Identify Network Interface
powershellGet-NetAdapter -Name *
Result: Identified interface index (ifIndex) = 5
Why This Matters: Windows uses interface index numbers for network configuration. This command identifies the correct adapter to configure, especially in systems with multiple network interfaces.
Step 2: Remove Existing Configuration
powershellRemove-NetIPAddress -InterfaceIndex 5 -Confirm:$false
Remove-NetRoute -InterfaceIndex 5 -Confirm:$false
Purpose:

Clears any previous IP addressing (DHCP or static)
Removes old routing entries
Ensures clean slate for new configuration
-Confirm:$false automates the process without prompts

Step 3: Configure Static IP Address
powershellNew-NetIPAddress -InterfaceIndex 5 -IPAddress 10.42.32.12 `
  -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 10.42.32.1
Configuration Breakdown:

10.42.32.12: Static IP on AdminNet segment
PrefixLength 24: Subnet mask 255.255.255.0 (CIDR /24)
DefaultGateway 10.42.32.1: pfSense LAN interface

Step 4: Configure DNS Servers
powershellSet-DnsClientServerAddress -InterfaceIndex 5 `
  -ServerAddresses ("8.8.8.8","8.8.4.4")
Why Google DNS?

Highly reliable public DNS servers
Low latency and fast resolution
8.8.8.8 (primary) and 8.8.4.4 (secondary) for redundancy


Phase 3: Network Migration - Ubuntu Client to ServerNet
Linux Network Reconfiguration Process
Modern Ubuntu Networking: Ubuntu 18.04+ uses Netplan for network configuration, replacing the older /etc/network/interfaces method.
Step 1: Edit Netplan Configuration
bashsudo nano /etc/netplan/01-network-manager-all.yaml
Configuration File Content:
yamlnetwork:
  version: 2
  renderer: networkd
  ethernets:
    ens33:  # Network interface name
      dhcp4: no
      addresses:
        - 10.43.32.11/24
      routes:
        - to: default
          via: 10.43.32.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
Configuration Explanation:

dhcp4: no - Disables DHCP, enables static IP
addresses: Static IP with CIDR notation
routes: Defines default gateway (all traffic via 10.43.32.1)
nameservers: DNS servers for domain resolution

Step 2: Generate and Apply Configuration
bashsudo netplan generate  # Validates and generates config
sudo netplan apply     # Applies the configuration
Step 3: Fix Permission Warnings
Issue: Netplan shows warnings about file permissions (security concern)
Solution:
bashsudo chmod 700 /etc/netplan/01-network-manager-all.yaml
Why This Matters:

Netplan files can contain sensitive information (Wi-Fi passwords, etc.)
Permissions should be restricted to root only (700 = rwx------)
Demonstrates security awareness and best practices
Clean output indicates professional system administration


Phase 4: Network Connectivity Validation
Ubuntu Linux Connectivity Tests
Test 1: Verify Routing Table
baship r
Expected Output:
default via 10.43.32.1 dev ens33
10.43.32.0/24 dev ens33 proto kernel scope link src 10.43.32.11
Analysis:

Default route points to pfSense ServerNet gateway (10.43.32.1)
Direct route to local subnet (10.43.32.0/24)
Confirms proper routing configuration

Test 2: Gateway Connectivity
bashping 10.43.32.1  # ServerNet gateway (local)
ping 10.42.32.1  # AdminNet gateway (routed through pfSense)
Purpose: Verifies both local gateway and inter-VLAN routing through pfSense
Test 3: Enterprise Network Gateway
bashping 192.168.254.254
Purpose: Tests connectivity to Gretzky Enterprise gateway, verifying routing beyond local segments
Test 4: Internet Connectivity
bashping 8.8.8.8      # Google DNS IP (tests Layer 3 connectivity)
ping dns.google   # Google DNS domain (tests DNS resolution)
Two-Layer Verification:

8.8.8.8: Confirms internet routing works
dns.google: Confirms DNS resolution is functional


Windows 10 Connectivity Tests
Test 1: Verify Network Configuration
cmdipconfig
Validates:

IP Address: 10.42.32.12
Subnet Mask: 255.255.255.0
Default Gateway: 10.42.32.1
DNS Servers: 8.8.8.8, 8.8.4.4

Test 2: Gateway Connectivity
cmdping 10.42.32.1  # AdminNet gateway (local)
ping 10.43.32.1  # ServerNet gateway (routed through pfSense)
Purpose: Validates routing between AdminNet and ServerNet through pfSense
Test 3: Enterprise Network Gateway
cmdping 192.168.254.254
Purpose: Confirms connectivity to external enterprise infrastructure
Test 4: Internet Connectivity
cmdping 8.8.8.8      # Google DNS IP
ping dns.google   # Google DNS domain
Test 5: External IP Verification

Navigated to whatismyipaddress.com
Confirmed public IP address (NAT performed by pfSense)

Why This Matters: Verifies that pfSense is properly performing Network Address Translation (NAT), allowing private IP addresses to access the internet through a single public IP.

Phase 5: pfSense Web Configuration
Accessing pfSense Web Interface
Access Method:

From Windows client, navigated to: http://10.42.32.1
Credentials: admin / pfsense

Why Web GUI?

More user-friendly than command-line for complex configurations
Visual representation of firewall rules and network status
Industry-standard administration method
Audit logging of configuration changes

Interface Renaming for Clarity
Standard pfSense Interface Names:

em0, em1, em2 (generic BSD interface names)

Renamed to Descriptive Names:

em0 → External: WAN connection to internet
em1 → AdminNet: Administrative workstation network
em2 → ServerNet: Server infrastructure network

Professional Practice: Descriptive interface names improve:

Configuration clarity
Troubleshooting efficiency
Documentation accuracy
Team collaboration

Configuration Path: Interfaces → (Interface Name) → General Configuration → Description

Phase 6: Intrusion Detection System Deployment
Suricata IDS Installation
Installation Process:

Navigated to: System → Package Manager
Searched for "Suricata"
Clicked "Install" and confirmed installation
Waited for package installation to complete

What is Suricata?

Open-source Network IDS/IPS (Intrusion Detection/Prevention System)
Monitors network traffic for malicious activity
Uses signature-based and anomaly-based detection
Can operate in passive (IDS) or inline (IPS) mode

Why Suricata?

Industry-standard network security monitoring tool
High-performance multi-threaded architecture
Supports emerging threats rule updates
Integrates with SIEM systems for security operations

Suricata Configuration
Configuration Steps:
1. Access Suricata Settings

Path: Services → Suricata

2. Configure Log Management

Set "Captured Files Retention Period" to 14 days

Why 14 Days?

Balances storage requirements with forensic investigation needs
Provides sufficient time to detect and investigate incidents
Complies with many security compliance frameworks
Prevents disk space exhaustion from excessive logging

3. Interface Configuration

Clicked "Add" to create new interface monitoring
Selected External (em0) interface
Saved configuration

Why Monitor External Interface?

All internet traffic passes through this interface
Highest risk of external attacks and threats
Monitors both inbound (attacks) and outbound (data exfiltration)
First line of defense against network-based threats

4. Enable Suricata

Clicked "Play" button to start Suricata service
Verified service status showing "Running"

Security Benefit: With Suricata monitoring the External interface, the network now has:

Real-time threat detection
Traffic logging for forensic analysis
Alerting on suspicious network patterns
Compliance with security monitoring requirements


🏗️ Network Architecture Analysis
Topology Overview
The implemented network architecture follows enterprise security best practices with multiple security zones:
                    [Internet]
                        |
                  [External IF]
                  192.168.254.254
                        |
                  [pfSense Router]
                   (Suricata IDS)
                        |
        +---------------+---------------+
        |                               |
    [AdminNet IF]                 [ServerNet IF]
    10.42.32.1/24                10.43.32.1/24
        |                               |
    [Windows 10]                   [Ubuntu Linux]
    10.42.32.12                    10.43.32.11
Security Zones Explained
1. External Zone (Internet)

Risk Level: Highest
Trust Level: Zero Trust
Protection: Suricata IDS monitors all traffic
Function: Provides internet connectivity

2. AdminNet (Administrative Network)

Risk Level: Medium
Trust Level: Trusted Users
Hosts: Windows 10 workstation
Function: Administrative access and management
Typical Use: System administrators, help desk, management

3. ServerNet (Server Network)

Risk Level: Medium-High
Trust Level: Controlled Access
Hosts: Ubuntu Linux server
Function: Backend services and applications
Typical Use: Web servers, database servers, application servers

Network Segmentation Benefits
Security Advantages:

Lateral Movement Prevention: Attackers compromising one segment can't easily access others
Blast Radius Containment: Security incidents are isolated to specific zones
Granular Access Control: Different firewall rules for each network segment
Compliance: Meets PCI-DSS, HIPAA, and other regulatory requirements
Traffic Monitoring: Easier to identify anomalous inter-segment communication

Operational Advantages:

Performance: Reduced broadcast domains improve network efficiency
Troubleshooting: Easier to isolate network issues to specific segments
Scalability: Additional segments can be added without disrupting existing networks
Quality of Service: Different QoS policies per network segment


🎓 Key Takeaways & Skills Demonstrated
Technical Skills

Enterprise Network Infrastructure

Designed and implemented multi-segment network architecture
Configured enterprise-grade firewall/router (pfSense)
Established routing between isolated network segments


Advanced Command-Line Administration

Windows PowerShell: Network interface configuration using modern cmdlets
Linux netplan: Modern Ubuntu networking with YAML configuration
pfSense CLI: Package management and service control


Network Security Implementation

Deployed Intrusion Detection System (Suricata)
Configured security monitoring on critical interfaces
Implemented network segmentation for defense-in-depth


Cross-Platform Networking

Configured static IP addressing on both Windows and Linux
Understood platform-specific networking tools and methodologies
Validated connectivity across different operating systems


Professional Network Administration

Used descriptive naming conventions for clarity
Documented network topology and configuration
Applied security best practices (file permissions, firewall configuration)




🔐 Cybersecurity Implications
Defense in Depth Strategy
This lab implements multiple security layers:

Network Segmentation: Isolates different security zones
Firewall Filtering: Controls traffic between segments (when enabled)
Intrusion Detection: Monitors for malicious network activity
Static IP Addressing: Prevents unauthorized DHCP-based attacks
DNS Configuration: Uses trusted external DNS (prevents DNS hijacking)

Attack Surface Reduction
What This Architecture Prevents:

Lateral Movement: Attackers on AdminNet can't directly access ServerNet
Network Scanning: Segmentation limits reconnaissance scope
Broadcast Attacks: VLANs isolate broadcast domains
Unauthorized Access: Firewall rules (when enabled) restrict inter-zone traffic

Monitoring & Incident Response
Suricata IDS Capabilities:

Real-time Alerts: Immediate notification of suspicious activity
Traffic Logging: 14-day retention for forensic investigation
Threat Intelligence: Uses community and commercial rule sets
PCAP Capture: Full packet capture for detailed analysis

Incident Response Readiness:

Network topology documented for rapid understanding
Clear segmentation makes containment easier
IDS logs provide evidence for investigation
Multiple test points for connectivity validation


🚀 Real-World Applications
IT Infrastructure Roles
Network Engineer:

Design and implement segmented network architectures
Configure enterprise routers and firewalls
Manage routing between network segments

System Administrator:

Configure network settings on Windows and Linux servers
Troubleshoot connectivity issues across platforms
Implement network security best practices

Security Administrator:

Deploy and maintain IDS/IPS systems
Configure firewall rules for network segmentation
Monitor security logs for threat detection

Cybersecurity Careers
Security Operations Center (SOC) Analyst:

Monitor Suricata alerts for security incidents
Investigate suspicious network traffic
Correlate IDS alerts with other security events

Penetration Tester:

Understand network segmentation to test security boundaries
Identify potential lateral movement paths
Validate firewall rule effectiveness

Incident Response Analyst:

Use network logs for forensic investigation
Understand routing to trace attack paths
Isolate compromised network segments

Cloud Security Engineer:

Apply segmentation concepts to cloud VPC design
Configure security groups and network ACLs
Implement defense-in-depth in cloud environments


📊 Performance & Configuration Metrics
Network Configuration Summary
ComponentConfigurationStatuspfSense VersionCE 2.7.2✅ InstalledOpen-VM-ToolsLatest✅ InstalledNetwork Segments3 (External, AdminNet, ServerNet)✅ ConfiguredSuricata IDSLatest✅ RunningWindows ClientStatic IP✅ ConnectedUbuntu ClientStatic IP✅ Connected
Connectivity Test Results
Test TypeSourceDestinationResultLocal GatewayUbuntu10.43.32.1✅ SuccessInter-VLANUbuntu10.42.32.1✅ SuccessEnterprise GWUbuntu192.168.254.254✅ SuccessInternet IPUbuntu8.8.8.8✅ SuccessInternet DNSUbuntudns.google✅ SuccessLocal GatewayWindows10.42.32.1✅ SuccessInter-VLANWindows10.43.32.1✅ SuccessEnterprise GWWindows192.168.254.254✅ SuccessInternet IPWindows8.8.8.8✅ SuccessInternet DNSWindowsdns.google✅ Success
Result: 100% connectivity success across all network segments and platforms

📚 Commands Reference
pfSense Commands
bash# At pfSense console menu
13                          # Update from Console
8                           # Shell access
pfctl -d                    # Disable firewall
pfctl -e                    # Enable firewall
pkg install <package>       # Install package
service -l | grep vmware    # List VMware services
Windows PowerShell Commands
powershell# Network interface management
Get-NetAdapter -Name *                              # List all network adapters
Remove-NetIPAddress -InterfaceIndex <Y> -Confirm:$false   # Remove IP config
Remove-NetRoute -InterfaceIndex <Y> -Confirm:$false       # Remove routes

# Configure static IP
New-NetIPAddress -InterfaceIndex <Y> -IPAddress <IP> `
  -AddressFamily IPv4 -PrefixLength <PREFIX> -DefaultGateway <GW>

# Configure DNS
Set-DnsClientServerAddress -InterfaceIndex <Y> `
  -ServerAddresses ("8.8.8.8","8.8.4.4")

# Verification
ipconfig                    # Display network configuration
ipconfig /all               # Display detailed configuration
ping <target>               # Test connectivity
Linux Networking Commands
bash# Netplan configuration
sudo nano /etc/netplan/01-network-manager-all.yaml   # Edit config
sudo netplan generate                                 # Generate config
sudo netplan apply                                    # Apply config
sudo chmod 700 /etc/netplan/*.yaml                   # Secure permissions

# Verification
ip r                        # Display routing table
ip a                        # Display interface addresses
ping <target>               # Test connectivity
ping -c 4 <target>          # Ping with count limit

🎯 Next Steps & Advanced Scenarios
Firewall Rule Configuration

Next Lab: Configure pfSense firewall rules to restrict inter-VLAN traffic
Skill: Implement least-privilege network access control
Scenario: Allow only specific services between AdminNet and ServerNet

VPN Implementation

Technology: pfSense OpenVPN or IPsec
Use Case: Secure remote access to internal networks
Skill: Encrypted tunnel configuration

High Availability

Configuration: pfSense CARP (Common Address Redundancy Protocol)
Benefit: Redundant firewalls for zero downtime
Skill: Enterprise-level availability design

Advanced IDS Configuration

Ruleset Management: Enable and configure Emerging Threats rules
Alert Tuning: Reduce false positives
SIEM Integration: Forward Suricata logs to centralized logging


💡 Lessons Learned
Technical Insights

Network Segmentation is Essential: Physical or logical separation dramatically improves security posture
Static vs DHCP: Static IPs provide stability for infrastructure but require careful documentation
Cross-Platform Consistency: Same networking principles apply, but implementation differs significantly
IDS Placement Matters: Monitoring external interfaces catches threats before they reach internal networks

Professional Practices

Documentation is Critical: Clear topology diagrams and configuration records enable effective troubleshooting
Descriptive Naming: Using meaningful names (AdminNet vs em1) improves operational efficiency
Security Best Practices: File permissions, firewall management, and monitoring should be considered from day one
Systematic Testing: Methodical connectivity validation ensures configuration correctness

Security Mindset

Defense in Depth: Multiple security layers provide resilience against attacks
Visibility is Key: You can't protect what you can't see (hence IDS deployment)
Least Privilege: Network segmentation enables granular access control
Monitoring Retention: Balance storage costs with forensic investigation needs


🔗 Related Skills & Technologies
Complementary Technologies

VLANs: Layer 2 network segmentation (logical separation on same physical switch)
ACLs: Access Control Lists for router-based filtering
SDN: Software-Defined Networking for programmatic network management
Zero Trust Architecture: Modern security model assuming breach

Related Tools

Snort: Alternative IDS/IPS system
Zeek (Bro): Network analysis and security monitoring
Wireshark: Packet capture and analysis
pfBlockerNG: pfSense package for DNS/IP blocking

Industry Certifications Aligned

CompTIA Network+: Basic networking and routing
Cisco CCNA: Enterprise networking fundamentals
CompTIA Security+: Network security concepts
Palo Alto PCNSA: Next-generation firewall administration
GIAC GCIA: Intrusion detection and analysis


📸 Lab Evidence
All screenshots demonstrating successful completion are documented in the original lab report, including:

✅ pfSense installation and Open-VM-Tools verification
✅ Windows PowerShell network configuration
✅ Linux netplan configuration and permission fixes
✅ Complete connectivity tests (10 successful ping tests)
✅ pfSense web interface configuration
✅ Interface renaming for clarity
✅ Suricata IDS installation and activation
✅ Network topology diagrams (internal and external)


🏆 Lab Status
Completion Status: ✅ Successfully Completed
All Connectivity Tests: ✅ 10/10 Passed
IDS Deployment: ✅ Suricata Running
Network Segments: ✅ 3 Configured
Documentation: ✅ Complete with topology

🔍 Troubleshooting Notes
Common Issues Encountered & Resolved
Issue 1: Netplan Permission Warnings

Problem: Warning messages about YAML file permissions
Solution: sudo chmod 700 /etc/netplan/*.yaml
Lesson: Security-conscious configuration from the start

Issue 2: Inter-VLAN Connectivity

Potential Issue: Firewall blocking legitimate traffic
Solution: Temporarily disabled firewall with pfctl -d
Production Note: Configure proper firewall rules instead

Issue 3: DNS Resolution Failures

Diagnosis: Ping 8.8.8.8 works, but ping dns.google fails
Cause: DNS server not configured
Solution: Set DNS servers (8.8.8.8, 8.8.4.4) in network config
