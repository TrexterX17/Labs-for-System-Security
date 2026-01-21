# Lab 05: Linux Server Hardening & Automation

## 📋 Lab Overview

**Difficulty Level:** Advanced  


### Objective
This lab demonstrates advanced Linux system administration and security hardening by deploying web and database servers, implementing user and group management, applying security hardening techniques, and automating log backup with cron jobs. This simulates enterprise Linux infrastructure where security baseline configurations and automated maintenance are critical.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Linux Server Deployment:** Installing and configuring Ubuntu (web server) and Rocky Linux (database server)
- **Web Server Administration:** Deploying Apache2 with PHP and associated modules
- **Database Server Setup:** Installing and configuring MariaDB on Rocky Linux
- **User & Group Management:** Creating users, groups, and implementing access control
- **Linux Security Hardening:** Password policies, sudo permissions, file permissions, SELinux
- **System Automation:** Creating bash scripts and scheduling with cron
- **Log Management:** Implementing automated log backup and rotation
- **Firewall Configuration:** Managing pfSense rules for Linux server access
- **Cross-Distribution Skills:** Working with both Debian-based (Ubuntu) and RHEL-based (Rocky Linux) systems

---

## 🛠️ Tools & Technologies Used

### Linux Distributions
- **Ubuntu Server** - Debian-based distribution for web server (apt package manager)
- **Rocky Linux** - RHEL-based distribution for database server (yum/dnf package manager)

### Server Software
| Software | Purpose | Installation |
|----------|---------|--------------|
| **Apache2** | Web server (HTTP/HTTPS) | apt install apache2 |
| **PHP 8.x** | Server-side scripting | Multiple php-* packages |
| **MariaDB** | MySQL-compatible database | yum install mariadb-server |
| **OpenSSH** | Secure remote access | openssh-server |
| **Open-VM-Tools** | VMware guest integration | open-vm-tools |

### Security & Hardening Tools
- **PAM (Pluggable Authentication Modules)** - Authentication framework
- **libpam-pwquality** - Password quality checking library
- **sudo/visudo** - Privilege escalation control
- **chmod/chown** - File permission management
- **unattended-upgrades** - Automatic security updates

### Automation Tools
- **Bash scripting** - Shell script automation
- **Cron** - Time-based job scheduler
- **tar** - Archive and compression utility

---

## 🏗️ Lab Environment Architecture

### Network Topology

```
                        [Internet]
                            |
                      [pfSense Router]
                      (Firewall Rules)
                            |
            +---------------+---------------+
            |                               |
        [AdminNet]                     [ServerNet]
        10.42.32.0/24                 10.43.32.0/24
            |                               |
        [Win10]                    +--------+--------+
        10.42.32.12                |        |        |
                              [ADServer][Ubuntu][Rocky]
                              10.43.32.10 WebServer DBServer
                                         10.43.32.11 10.43.32.X

                        [External Network - Gretzky Red]
                                    |
                              [OutsideDevice]
                           (Simulated External)

DOMAIN: team32.local
Web Server: UbuntuWebServer (Apache2 + PHP)
Database Server: RockyDBServer (MariaDB)
```

### Server Specifications

**UbuntuWebServer:**
- **OS:** Ubuntu Server 22.04 LTS
- **IP Address:** 10.43.32.11/24
- **Gateway:** 10.43.32.1 (pfSense)
- **Services:** Apache2, PHP 8.1, SSH
- **Purpose:** Web application hosting

**RockyDBServer:**
- **OS:** Rocky Linux 9
- **IP Address:** 10.43.32.X/24
- **Gateway:** 10.43.32.1 (pfSense)
- **Services:** MariaDB, SSH
- **Purpose:** Database backend

---

## 📝 Methodology & Implementation

### Phase 1: Firewall Configuration for Linux Servers

#### Understanding the Network Security Model

**Three-Tier Architecture:**
1. **Presentation Tier:** AdminNet (client workstations)
2. **Application Tier:** ServerNet (web servers)
3. **Data Tier:** ServerNet (database servers)

**Security Principle:** Network segmentation with strict firewall rules between tiers.

#### Task 1.1: AdminNet Firewall Rules

**Rule 1: Allow AdminNet → pfSense Management**
- **Interface:** AdminNet
- **Action:** Allow
- **Protocol:** TCP
- **Source:** AdminNet subnet (10.42.32.0/24)
- **Destination:** pfSense (This Firewall)
- **Destination Port:** HTTPS (443)
- **Description:** "Allow AdminNet to access pfSense webConfigurator"

**Purpose:**
Allows administrators from AdminNet to manage the firewall. Previously only Win10Client could access pfSense; this broadens access to the entire admin subnet while still excluding ServerNet.

**Security Consideration:**
- More permissive than previous Lab 03 (single device)
- Trade-off: Easier administration vs. smaller attack surface
- Production: Consider VPN + bastion host instead

#### Task 1.2: ServerNet Firewall Rules

**Rule 1: Block External → ServerNet (Default Deny)**
- **Interface:** External
- **Action:** Block
- **Protocol:** Any
- **Source:** Any (Internet)
- **Destination:** ServerNet subnet (10.43.32.0/24)
- **Description:** "Block all inbound traffic from external to ServerNet"

**Purpose:**
Prevents direct internet access to servers. All external access must route through proper channels (reverse proxy, VPN, etc.).

**Rule 2: Allow AdminNet → ServerNet**
- **Interface:** AdminNet
- **Action:** Allow
- **Protocol:** Any (or specific: SSH, HTTP)
- **Source:** AdminNet subnet
- **Destination:** ServerNet subnet
- **Description:** "Allow AdminNet to access ServerNet for management"

**Purpose:**
Administrators can manage servers (SSH, web admin panels) from their workstations.

**Rule 3: Allow HTTP from ServerNet**
- **Interface:** ServerNet
- **Action:** Allow
- **Protocol:** TCP
- **Source:** ServerNet subnet
- **Destination:** Any
- **Destination Port:** HTTP (80)
- **Description:** "Allow ServerNet HTTP outbound"

**Purpose:**
Servers can download packages, updates, and access external web resources.

**Rule 4: Allow HTTPS from ServerNet**
- **Interface:** ServerNet
- **Action:** Allow
- **Protocol:** TCP
- **Source:** ServerNet subnet
- **Destination:** Any
- **Destination Port:** HTTPS (443)
- **Description:** "Allow ServerNet HTTPS outbound"

**Purpose:**
Secure communications for package downloads, API calls, certificate validation.

**Rule 5: Allow DNS from ServerNet**
- **Interface:** ServerNet
- **Action:** Allow
- **Protocol:** UDP (and TCP for large responses)
- **Source:** ServerNet subnet
- **Destination:** Any (or specific DNS servers)
- **Destination Port:** DNS (53)
- **Description:** "Allow ServerNet DNS queries"

**Purpose:**
Name resolution for package repositories, external APIs, database connections.

**Rule 6: Allow ICMP from ServerNet**
- **Interface:** ServerNet
- **Action:** Allow
- **Protocol:** ICMP
- **Source:** ServerNet subnet
- **Destination:** Any
- **Description:** "Allow ServerNet ping for diagnostics"

**Purpose:**
Network troubleshooting and connectivity testing.

**Security Architecture Summary:**
```
Internet → [BLOCKED] → ServerNet
AdminNet → [ALLOWED] → ServerNet (management)
ServerNet → [ALLOWED] → Internet (HTTP/HTTPS/DNS/ICMP only)
```

This implements defense-in-depth: servers cannot be accessed from internet, administrators have controlled access, servers have limited outbound access.

---

### Phase 2: Ubuntu Web Server Deployment

#### Task 2.1: Network Configuration Verification

**Command:**
```bash
ip r
```

**Purpose:**
Displays routing table to verify:
- Default gateway configured (10.43.32.1)
- Local subnet route exists
- Network interface operational

**Expected Output:**
```
default via 10.43.32.1 dev ens33
10.43.32.0/24 dev ens33 proto kernel scope link src 10.43.32.11
```

**What This Shows:**
- All non-local traffic routes through 10.43.32.1 (pfSense)
- Direct routing for local subnet 10.43.32.0/24
- Interface ens33 is operational with IP 10.43.32.11

#### Task 2.2: Internet Connectivity Test

**Command:**
```bash
ping 8.8.8.8
```

**Purpose:**
Validates internet connectivity through pfSense router.

**What Success Indicates:**
- ✅ Network interface functioning
- ✅ Default gateway reachable
- ✅ pfSense routing traffic correctly
- ✅ Firewall rules allowing outbound ICMP
- ✅ DNS servers accessible (if using domain name)

#### Task 2.3: System Updates

**Command:**
```bash
sudo apt update
```

**What This Does:**
- Updates package index from Ubuntu repositories
- Refreshes list of available packages and versions
- Does NOT install updates (just updates the list)

**Why This First:**
- Ensures latest package versions available
- Prevents installing outdated software
- Security best practice: always update before installing

**Follow-up (Recommended):**
```bash
sudo apt upgrade -y  # Install available updates
```

#### Task 2.4: VMware Tools Installation

**Command:**
```bash
sudo apt install open-vm-tools
```

**What is Open-VM-Tools?**
Open-source implementation of VMware Tools providing:
- Better performance (optimized drivers)
- Time synchronization with host
- Guest information to hypervisor
- Copy/paste between host and guest
- Shared folders (if configured)

**Verification:**
```bash
sudo systemctl status open-vm-tools
```

**Expected Status:**
```
● open-vm-tools.service - Service for virtual machines hosted on VMware
   Active: active (running)
```

**Production Note:**
In cloud environments (AWS, Azure), use equivalent tools:
- AWS: amazon-ssm-agent
- Azure: walinuxagent
- GCP: google-guest-agent

#### Task 2.5: Apache2 and PHP Stack Installation

**Command (Single Line):**
```bash
sudo apt install apache2 libapache2-mod-php php php-mysql \
  php-xml php-mbstring php-apcu php-intl php-gd php-cli \
  php-curl imagemagick inkscape git openssh-server
```

**Package Breakdown:**

**Core Web Server:**
- **apache2** - Apache HTTP Server (world's most popular web server)
- **libapache2-mod-php** - PHP module for Apache

**PHP and Extensions:**
- **php** - PHP interpreter (server-side scripting language)
- **php-mysql** - MySQL/MariaDB database connectivity
- **php-xml** - XML processing (required by many CMSs)
- **php-mbstring** - Multi-byte string handling (international characters)
- **php-apcu** - Alternative PHP Cache (performance)
- **php-intl** - Internationalization support
- **php-gd** - Image processing library
- **php-cli** - Command-line PHP interface
- **php-curl** - cURL support (HTTP requests)

**Additional Tools:**
- **imagemagick** - Image manipulation command-line tool
- **inkscape** - Vector graphics editor (optional)
- **git** - Version control system
- **openssh-server** - SSH daemon for remote access

**What This Stack Supports:**
- WordPress, Drupal, Joomla (content management)
- Custom PHP web applications
- RESTful APIs
- Database-driven websites
- Image galleries and processing

**Post-Installation Verification:**
```bash
# Check Apache status
sudo systemctl status apache2

# Check PHP version
php -v

# Test Apache (from another machine)
curl http://10.43.32.11
```

**Expected Result:**
Apache2 default page displays, showing successful installation.

**Security Considerations:**
- Disable directory listing: Edit /etc/apache2/apache2.conf
- Change default error pages (information disclosure)
- Remove version headers (ServerTokens Prod)
- Enable mod_security (Web Application Firewall)
- Configure SSL/TLS certificates (Let's Encrypt)

---

### Phase 3: Rocky Linux Database Server Deployment

#### Understanding Rocky Linux

**What is Rocky Linux?**
- RHEL-compatible distribution (successor to CentOS)
- Enterprise-grade stability
- 10-year support lifecycle
- Binary compatible with RHEL
- Uses RPM packages and yum/dnf package managers

**Debian vs. RHEL Differences:**

| Feature | Ubuntu (Debian) | Rocky Linux (RHEL) |
|---------|----------------|-------------------|
| Package Manager | apt | yum/dnf |
| Package Format | .deb | .rpm |
| Init System | systemd | systemd |
| Default Firewall | UFW | firewalld |
| SELinux | Available (not default) | Enforced by default |
| Release Cycle | 6 months (LTS: 5 years) | 10 years |

#### Task 3.1: Network Verification

**Command:**
```bash
ip r
```

**Same purpose as Ubuntu, validates routing configuration.**

#### Task 3.2: Connectivity Test

**Command:**
```bash
ping 8.8.8.8
```

**Validates internet access through pfSense.**

#### Task 3.3: System Updates (RHEL/Rocky)

**Command:**
```bash
sudo yum update
```

**Equivalent to `apt update && apt upgrade` on Ubuntu.**

**What This Does:**
- Checks for package updates
- Downloads and installs updates
- Updates kernel (requires reboot)
- Applies security patches

**Alternative (Rocky Linux 9):**
```bash
sudo dnf update  # dnf is the modern replacement for yum
```

**Production Best Practice:**
```bash
# Check what will be updated first
sudo yum check-update

# Update only security patches
sudo yum update --security

# Exclude specific packages (like kernel during business hours)
sudo yum update --exclude=kernel*
```

#### Task 3.4: VMware Tools Installation (Rocky)

**Command:**
```bash
sudo yum install open-vm-tools
```

**Enable and Start Service:**
```bash
sudo systemctl enable vmtoolsd
sudo systemctl start vmtoolsd
```

**Why Enable?**
- Ensures service starts automatically on boot
- Without enable: service stops after reboot

**Verification:**
```bash
sudo systemctl status vmtoolsd
```

**Expected Output:**
```
● vmtoolsd.service - Service for virtual machines hosted on VMware
   Active: active (running)
   Enabled: yes
```

#### Task 3.5: MariaDB Installation

**Command:**
```bash
sudo yum install mariadb-server
```

**What is MariaDB?**
- MySQL fork created by original MySQL developers
- Fully compatible with MySQL
- Enhanced features and performance
- Default in RHEL/Rocky Linux

**Post-Installation Steps (Production):**

**1. Enable and Start Service:**
```bash
sudo systemctl enable mariadb
sudo systemctl start mariadb
sudo systemctl status mariadb
```

**2. Secure Installation:**
```bash
sudo mysql_secure_installation
```

**This wizard prompts for:**
- Set root password
- Remove anonymous users (YES)
- Disallow root login remotely (YES)
- Remove test database (YES)
- Reload privilege tables (YES)

**3. Test Database Access:**
```bash
mysql -u root -p
```

**4. Create Application Database:**
```sql
CREATE DATABASE webapp_db;
CREATE USER 'webuser'@'10.43.32.11' IDENTIFIED BY 'StrongPassword123!';
GRANT ALL PRIVILEGES ON webapp_db.* TO 'webuser'@'10.43.32.11';
FLUSH PRIVILEGES;
```

**Why Separate Web and Database Servers?**
1. **Security:** Database not directly exposed
2. **Performance:** Dedicated resources per tier
3. **Scalability:** Can scale web/db independently
4. **Maintenance:** Update/restart services without affecting other tier
5. **Compliance:** Many regulations require separation

**Connecting Web Server to Database:**
From UbuntuWebServer:
```php
connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully";
?>
```

---

### Phase 4: User and Group Management

#### Understanding Linux Users and Groups

**User Types:**
1. **System Users:** UID < 1000, service accounts (www-data, mysql)
2. **Regular Users:** UID ≥ 1000, human users
3. **Root User:** UID 0, superuser

**Group Types:**
1. **Primary Group:** User's default group (in /etc/passwd)
2. **Supplementary Groups:** Additional group memberships

**Important Files:**
- **/etc/passwd** - User account information
- **/etc/shadow** - Encrypted passwords
- **/etc/group** - Group information
- **/etc/gshadow** - Group passwords (rarely used)

#### Task 4.1: Create User with adduser (Interactive)

**Command:**
```bash
sudo adduser fahmed29
```

**What adduser Does (Ubuntu/Debian):**
1. Creates user account
2. Creates home directory (/home/fahmed29)
3. Copies skeleton files (.bashrc, .profile)
4. Creates private group (fahmed29)
5. Prompts for password
6. Prompts for user information (Full Name, Room, Phone, etc.)

**Interactive Prompts:**
```
Enter new UNIX password: Change.me!
Retype new UNIX password: Change.me!
Full Name []: Faraz Ahmed
Room Number []: (Enter for default)
Work Phone []: (Enter for default)
Home Phone []: (Enter for default)
Other []: (Enter for default)
Is the information correct? [Y/n] Y
```

**Verification:**
```bash
id fahmed29
# Output: uid=1001(fahmed29) gid=1001(fahmed29) groups=1001(fahmed29)

ls -la /home/fahmed29
# Shows home directory created with proper permissions
```

#### Task 4.2: Create User with useradd (Non-Interactive)

**Command:**
```bash
sudo useradd -m -s /bin/bash kpcleary
sudo passwd kpcleary
```

**Flag Explanation:**
- **-m** - Create home directory (not default on all systems)
- **-s /bin/bash** - Set default shell to bash
- Without these flags, user may not have home directory or interactive shell

**Set Password:**
```bash
sudo passwd kpcleary
```

**Prompts for password twice (without showing characters).**

**adduser vs. useradd:**

| Feature | adduser (Debian) | useradd (Universal) |
|---------|-----------------|-------------------|
| Interactivity | Interactive (prompts) | Non-interactive (flags) |
| Home Directory | Created automatically | Requires -m flag |
| Default Shell | Set automatically | Requires -s flag |
| User Info | Prompts for details | Not included |
| Portability | Debian/Ubuntu only | All Linux distributions |

**Production Best Practice:**
Use adduser for interactive sessions, useradd for scripts/automation.

#### Task 4.3: Create Groups and Add Members

**Create UBNetDef Group:**
```bash
sudo groupadd UBNetDef
```

**Add Users to Group:**
```bash
sudo usermod -aG UBNetDef vasudevb
sudo usermod -aG UBNetDef ethanvia
sudo usermod -aG UBNetDef pfox
sudo usermod -aG UBNetDef kpcleary
```

**Flag Explanation:**
- **-a** - Append (add to group without removing from others)
- **-G** - Supplementary group (not primary group)
- **Without -a:** User would be REMOVED from all other groups (dangerous!)

**Create BlackTeam Group:**
```bash
sudo groupadd BlackTeam
```

**Add Users:**
```bash
sudo usermod -aG BlackTeam vasudevb
sudo usermod -aG BlackTeam ethanvia
sudo usermod -aG BlackTeam pfox
```

**Create SysSec Group:**
```bash
sudo groupadd SysSec
```

**Add User:**
```bash
sudo usermod -aG SysSec fahmed29
```

**Verify Group Membership:**
```bash
getent group BlackTeam
# Output: BlackTeam:x:1002:vasudevb,ethanvia,pfox

groups vasudevb
# Output: vasudevb : vasudevb UBNetDef BlackTeam

id vasudevb
# Shows UID, GID, and all group memberships
```

**Use Cases for Groups:**
- **UBNetDef:** All team members (base permissions)
- **BlackTeam:** Offensive security team (elevated permissions)
- **SysSec:** System security administrators (full access)

**Real-World Examples:**
- **developers:** Can deploy code, access logs
- **dba:** Database administration rights
- **security:** Access to security tools and logs
- **audit:** Read-only access for compliance

---

### Phase 5: Linux Security Hardening

#### Understanding Linux Hardening

**Security Hardening:**
Process of reducing system attack surface by:
- Enforcing strong authentication
- Limiting user privileges
- Restricting file permissions
- Applying security policies
- Disabling unnecessary services

**Security Frameworks:**
- CIS Benchmarks (Center for Internet Security)
- NIST 800-53 Security Controls
- DISA STIGs (Security Technical Implementation Guides)
- PCI-DSS Requirements (for payment systems)

#### Task 5.1: Password Aging Policy

**Purpose:**
Force users to change passwords periodically to limit damage from compromised credentials.

**Configuration File: /etc/login.defs**

**Command:**
```bash
sudo nano /etc/login.defs
```

**Modify:**
```bash
PASS_MAX_DAYS   70   # Changed from 99999 (never expire)
```

**Other Password Aging Settings (Optional):**
```bash
PASS_MIN_DAYS   1    # Minimum days between password changes
PASS_MIN_LEN    10   # Minimum password length
PASS_WARN_AGE   7    # Days warning before password expires
```

**What This Does:**
- New users: Password expires after 70 days
- Existing users: NOT affected (must apply manually)

**Apply to Existing Users:**
```bash
sudo chage -M 70 fahmed29
sudo chage -l fahmed29  # List password aging info
```

**Production Consideration:**
Balance security vs. usability:
- Too short (30 days): Users write passwords down
- Too long (365 days): Compromised credentials valid longer
- Industry standard: 60-90 days

**Compliance Requirements:**
- PCI-DSS: 90 days maximum
- HIPAA: 90 days recommended
- NIST: No specific requirement (risk-based)

#### Task 5.2: Automatic Security Updates

**Command:**
```bash
sudo apt install unattended-upgrades
```

**What This Does:**
Automatically installs security updates without manual intervention.

**Configuration:**
```bash
sudo dpkg-reconfigure unattended-upgrades
# Select "Yes" when prompted
```

**Configuration File: /etc/apt/apt.conf.d/50unattended-upgrades**

**Recommended Settings:**
```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // "${distro_id}:${distro_codename}-updates";  // Commented out - only security
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";  // Change to true for automatic reboots
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

**Why Security Updates Only?**
- Security patches: Critical, well-tested
- General updates: May introduce breaking changes
- Production: Test updates in staging first

**Email Notifications:**
```bash
sudo apt install mailutils
```

Edit /etc/apt/apt.conf.d/50unattended-upgrades:
```
Unattended-Upgrade::Mail "admin@example.com";
Unattended-Upgrade::MailReport "on-change";
```

**Check Update Status:**
```bash
sudo cat /var/log/unattended-upgrades/unattended-upgrades.log
```

#### Task 5.3: Sudo Privilege Management

**Understanding sudo:**
- Allows unprivileged users to execute commands as root
- Better than logging in as root (audit trail)
- Principle of least privilege (temporary elevation)

**Configuration File: /etc/sudoers**
⚠️ **NEVER edit directly! Always use visudo!**

**Command:**
```bash
sudo visudo
```

**Why visudo?**
- Syntax checking before saving
- Prevents lockout from misconfiguration
- Locks file during editing

**Default Configuration:**
```
# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of admin group may gain root privileges
%admin  ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
```

**Add BlackTeam Group:**
```
%BlackTeam ALL=(ALL:ALL) ALL
```

**Syntax Explanation:**
```
%BlackTeam    ALL    =    (ALL:ALL)    ALL
   ↓          ↓      ↓        ↓         ↓
 Group     Hosts  Run as   Users:Groups Commands
```

- **%BlackTeam** - Group (% indicates group)
- **ALL** - From any host (relevant for NFS-mounted sudoers)
- **=(ALL:ALL)** - Run as any user:any group
- **ALL** - Execute any command

**Testing:**
```bash
su - vasudevb  # Switch to user (member of BlackTeam)
sudo vim       # Should now work (previously failed)
```

**Advanced sudo Configurations:**

**1. Allow Specific Commands Only:**
```
%developers ALL=(ALL) /usr/bin/systemctl restart apache2, /usr/bin/tail -f /var/log/apache2/*
```

**2. No Password Required (Dangerous!):**
```
%admins ALL=(ALL) NOPASSWD: ALL
```

**3. Limit to Specific Hosts:**
```
john webserver1=(ALL) ALL
```

**4. Run as Specific User:**
```
%dba ALL=(mysql) ALL
```

**5. Command Aliases:**
```
Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig, /bin/ping
%netadmin ALL = NETWORKING
```

**Security Best Practices:**
- Don't use NOPASSWD unless absolutely necessary
- Limit commands to specific paths (prevent PATH hijacking)
- Use command aliases for readability
- Log all sudo usage (enabled by default)
- Review sudo logs regularly: /var/log/auth.log

#### Task 5.4: File Permission Hardening

**Understanding Linux Permissions:**

**Permission Types:**
- **r (4):** Read
- **w (2):** Write  
- **x (1):** Execute

**Permission Targets:**
- **User (owner):** First 3 bits
- **Group:** Second 3 bits
- **Others:** Third 3 bits

**Examples:**
- **755:** rwxr-xr-x (owner: full, group/others: read+execute)
- **644:** rw-r--r-- (owner: read+write, group/others: read-only)
- **700:** rwx------ (owner: full, nobody else)

**Task 5.4.1: Restrict whoami Command**

**Command:**
```bash
sudo chmod 700 $(which whoami)
```

**Breakdown:**
- **$(which whoami)** - Finds path to whoami binary (/usr/bin/whoami)
- **chmod 700** - Sets permissions to rwx------
- **Result:** Only root can execute whoami

**Purpose (Security Testing):**
Demonstrates permission restriction effects. Regular users trying to run whoami will get "Permission denied".

**Verify:**
```bash
ls -l $(which whoami)
# Output: -rwx------ 1 root root 35280 /usr/bin/whoami

su - fahmed29
whoami  # Permission denied
```

**Restore (for lab purposes):**
```bash
sudo chmod 755 $(which whoami)
```

**Real-World Use Case:**
Restricting security-sensitive commands:
- netstat (network information disclosure)
- ss (socket statistics)
- ps (process listing - may reveal sensitive info)
- tcpdump (packet capture)

**Task 5.4.2: Restrict /etc/hostname**

**Command:**
```bash
sudo chmod 750 /etc/hostname
```

**Permissions: rwxr-x---**
- **Owner (root):** Read, write, execute
- **Group:** Read, execute
- **Others:** No access

**Change Ownership:**
```bash
sudo chown pcfox:pcfox /etc/hostname
```

**What This Does:**
- Changes owner from root to pcfox
- Changes group from root to pcfox

**Now Only:**
- pcfox (owner) can read/write
- Members of pcfox group can read
- Nobody else can access

**Purpose:**
Demonstrates file ownership and group-based access control.

**Verify:**
```bash
ls -l /etc/hostname
# Output: -rwxr-x--- 1 pcfox pcfox 13 /etc/hostname

# As another user (not pcfox, not in pcfox group):
cat /etc/hostname  # Permission denied

# As pcfox or members of BlackTeam (if pcfox added to BlackTeam):
cat /etc/hostname  # Works (read permission)
```

**Production Consideration:**
Be very careful changing ownership of system files! /etc/hostname should remain root:root in production. This is for educational purposes only.

#### Task 5.5: Password Quality Requirements

**Install PAM Password Quality Library:**
```bash
sudo apt install libpam-pwquality
```

**What is PAM (Pluggable Authentication Modules)?**
- Framework for authentication in Linux
- Modular approach (plug in different auth methods)
- Used by login, sudo, ssh, su, etc.

**Configuration File:**
```bash
sudo nano /etc/security/pwquality.conf
```

**Modify Settings:**

**1. Minimum Length:**
```
minlen = 10
```
Passwords must be at least 10 characters.

**2. Digit Requirement:**
```
dcredit = -2
```
- Negative value = minimum required
- Password must contain at least 2 digits (0-9)

**3. Uppercase Requirement:**
```
ucredit = -1
```
Password must contain at least 1 uppercase letter (A-Z).

**Other Available Settings:**
```
lcredit = -1        # Lowercase letters required
ocredit = -1        # Special characters required
minclass = 3        # Minimum character classes (upper, lower, digit, special)
maxrepeat = 3       # Maximum consecutive repeated characters
maxsequence = 3     # Maximum monotonic character sequence (abc, 123)
dictcheck = 1       # Check against dictionary words
usercheck = 1       # Reject passwords containing username
enforcing = 1       # Enforce (1) or warn only (0)
```

**Full Hardened Example:**
```
minlen = 14
dcredit = -2
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 2
maxsequence = 3
dictcheck = 1
usercheck = 1
enforcing = 1
```

**Test Password Quality:**
```bash
passwd  # Try to change your password

# Try weak password: "password"
# Result: BAD PASSWORD: The password fails the dictionary check

# Try short password: "Pass1!"
# Result: BAD PASSWORD: The password is shorter than 10 characters

# Try without digit: "Password"
# Result: BAD PASSWORD: The password contains less than 2 digits

# Try good password: "MyP@ssw0rd2024!"
# Result: Accepted (meets all requirements)
```

**Integration with PAM:**
Password quality automatically enforced for:
- passwd command
- useradd/usermod
- sudo password changes
- SSH password authentication
- GUI login

**Compliance Mapping:**
- **PCI-DSS 8.2.3:** Passwords must be minimum 7 characters and contain both letters and numbers
  - ✅ Our config: 10 char minimum, requires digits and uppercase
- **NIST SP 800-63B:** Minimum 8 characters, no complexity requirements (but longer is better)
  - ✅ Our config: 10 char minimum with complexity
- **CIS Benchmark:** Passwords at least 14 characters
  - ⚠️ Our config: 10 characters (adjust minlen = 14 for full CIS compliance)

---

### Phase 6: Log Management & Automation

#### Understanding Log Files in Linux

**Critical Log Locations:**
- **/var/log/syslog** - System-wide messages
- **/var/log/auth.log** - Authentication logs (sudo, SSH)
- **/var/log/apache2/access.log** - Web server access logs
- **/var/log/apache2/error.log** - Web server error logs
- **/var/log/mysql/error.log** - Database errors
- **/var/log/kern.log** - Kernel messages

**Why Log Management Matters:**
1. **Security:** Detect intrusions and attacks
2. **Compliance:** Regulatory requirements for log retention
3. **Troubleshooting:** Diagnose system issues
4. **Forensics:** Incident investigation
5. **Performance:** Identify bottlenecks

**Log Rotation:**
Prevents logs from filling up disk space. Automatic rotation based on:
- Size (e.g., when log reaches 100MB)
- Time (e.g., daily, weekly)
- Compression of old logs
- Deletion of very old logs

#### Task 6.1: Verify Apache Access Logs

**Command:**
```bash
cat /var/log/apache2/access.log
```

**Purpose:**
Check if access logs exist and contain entries.

**Expected Output (Empty Initially):**
No entries yet because no web traffic has occurred.

**After Accessing Web Server:**
```
10.42.32.12 - - [26/Sep/2024:14:23:45 +0000] "GET / HTTP/1.1" 200 3526
10.42.32.12 - - [26/Sep/2024:14:23:46 +0000] "GET /favicon.ico HTTP/1.1" 404 487
```

**Log Format Breakdown:**
```
10.42.32.12          - Client IP address
-                    - Remote logname (usually -)
-                    - Authenticated user (or - if none)
[26/Sep/2024:14:23]  - Timestamp
"GET / HTTP/1.1"     - Request method, path, protocol
200                  - HTTP status code (200 = OK)
3526                 - Response size in bytes
```

**Common HTTP Status Codes:**
- **200:** OK (success)
- **301/302:** Redirect
- **403:** Forbidden (access denied)
- **404:** Not Found
- **500:** Internal Server Error
- **502:** Bad Gateway (upstream server error)

**Security Analysis:**
Look for suspicious patterns:
- 404 spam (directory scanning)
- 403s (unauthorized access attempts)
- Unusual user agents
- SQL injection attempts in URLs
- Excessive requests from single IP (DoS)

#### Task 6.2: Create Log Backup Directory

**Command:**
```bash
mkdir /home/sysadmin/log_backups
```

**Purpose:**
Centralized location for archived log files.

**Alternative Locations:**
- **/var/backups/logs** - System-wide backup location
- **/opt/log_backups** - Third-party application area
- Remote server via rsync/scp (best practice)

**Permissions:**
```bash
chmod 750 /home/sysadmin/log_backups
```
Only sysadmin and group can access (logs may contain sensitive info).

#### Task 6.3: Create Log Backup Script

**Command:**
```bash
nano /home/sysadmin/backuplog.sh
```

**Script Content:**
```bash
#!/bin/bash
# Log Backup Script
# Archives Apache access logs daily

# Variables
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SOURCE_LOG="/var/log/apache2/access.log"
BACKUP_DIR="/home/sysadmin/log_backups"
BACKUP_FILE="access_log_${TIMESTAMP}.tar.gz"

# Create compressed archive
tar -czf ${BACKUP_DIR}/${BACKUP_FILE} ${SOURCE_LOG}

# Optional: Clear source log after backup
# > ${SOURCE_LOG}

# Optional: Delete backups older than 30 days
# find ${BACKUP_DIR} -name "access_log_*.tar.gz" -mtime +30 -delete

echo "Log backup completed: ${BACKUP_FILE}"
```

**Script Breakdown:**

**1. Shebang Line:**
```bash
#!/bin/bash
```
Tells system to execute script with bash interpreter.

**2. Variables:**
```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
```
Creates timestamp: 20240926_142345 (year, month, day, hour, minute, second)

**3. Archive Creation:**
```bash
tar -czf ${BACKUP_DIR}/${BACKUP_FILE} ${SOURCE_LOG}
```
- **tar:** Archive utility
- **-c:** Create new archive
- **-z:** Compress with gzip
- **-f:** Specify filename

**4. Optional: Clear Log (Commented Out):**
```bash
# > ${SOURCE_LOG}
```
Truncates log file after backup (optional, be careful!)

**5. Optional: Retention Policy:**
```bash
# find ${BACKUP_DIR} -name "access_log_*.tar.gz" -mtime +30 -delete
```
Deletes backup files older than 30 days (compliance requirement).

**Enhanced Script (Production):**
```bash
#!/bin/bash
# Enhanced Log Backup Script with Error Handling

set -e  # Exit on error
set -u  # Exit on undefined variable

# Variables
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SOURCE_LOG="/var/log/apache2/access.log"
BACKUP_DIR="/home/sysadmin/log_backups"
BACKUP_FILE="access_log_${TIMESTAMP}.tar.gz"
LOG_FILE="/var/log/backup.log"
RETENTION_DAYS=30

# Functions
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a ${LOG_FILE}
}

# Check if source log exists
if [ ! -f "${SOURCE_LOG}" ]; then
    log_message "ERROR: Source log not found: ${SOURCE_LOG}"
    exit 1
fi

# Check if backup directory exists, create if not
if [ ! -d "${BACKUP_DIR}" ]; then
    mkdir -p "${BACKUP_DIR}"
    log_message "Created backup directory: ${BACKUP_DIR}"
fi

# Create backup
if tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" "${SOURCE_LOG}" 2>> ${LOG_FILE}; then
    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    log_message "SUCCESS: Backup created (${BACKUP_SIZE}): ${BACKUP_FILE}"
else
    log_message "ERROR: Backup failed"
    exit 1
fi

# Delete old backups
DELETED=$(find "${BACKUP_DIR}" -name "access_log_*.tar.gz" -mtime +${RETENTION_DAYS} -delete -print | wc -l)
if [ ${DELETED} -gt 0 ]; then
    log_message "Deleted ${DELETED} old backup(s) older than ${RETENTION_DAYS} days"
fi

log_message "Backup completed successfully"
exit 0
```

#### Task 6.4: Make Script Executable

**Command:**
```bash
chmod +x /home/sysadmin/backuplog.sh
```

**Permission Breakdown:**
- **+x:** Add execute permission
- Without execute permission, script cannot run

**Verify:**
```bash
ls -la /home/sysadmin/backuplog.sh
```

**Expected Output:**
```
-rwxrwxr-x 1 sysadmin sysadmin 456 Sep 26 14:30 backuplog.sh
```

**Permission Analysis:**
- **-rwxrwxr-x:**
  - Owner (sysadmin): Read, Write, Execute
  - Group: Read, Write, Execute
  - Others: Read, Execute

**Security Consideration:**
For production scripts:
```bash
chmod 750 /home/sysadmin/backuplog.sh
chown root:sysadmin /home/sysadmin/backuplog.sh
```
- Only root and sysadmin group can execute
- Others cannot even read (may contain passwords/keys)

**Test Script Manually:**
```bash
/home/sysadmin/backuplog.sh
# Or
bash /home/sysadmin/backuplog.sh
```

#### Task 6.5: Schedule with Cron

**Understanding Cron:**
- Time-based job scheduler
- Runs commands/scripts at specified intervals
- Each user has own crontab
- System-wide cron in /etc/crontab

**Cron Syntax:**
```
* * * * * command
│ │ │ │ │
│ │ │ │ └─── Day of week (0-7, Sunday = 0 or 7)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

**Special Characters:**
- **\*:** Any value
- **,:** Value list (1,3,5)
- **-:** Range (1-5)
- **/:** Step values (*/15 = every 15 minutes)

**Edit Crontab:**
```bash
crontab -e
```

**Select Editor:**
First time: Choose nano (easiest for beginners)

**Add Line:**
```
5 4 * * * /home/sysadmin/backuplog.sh
```

**Translation:**
- Run every day
- At 4:05 AM
- Execute /home/sysadmin/backuplog.sh

**Why 4:05 AM?**
- Low traffic period (minimal impact)
- Before business hours (backups complete before work starts)
- Standard maintenance window
- Offset from hourly tasks (4:00) to distribute load

**Common Cron Examples:**
```bash
# Every minute (testing)
* * * * * /path/to/script.sh

# Every hour at minute 0
0 * * * * /path/to/script.sh

# Every day at noon
0 12 * * * /path/to/script.sh

# Every Monday at 3:30 AM
30 3 * * 1 /path/to/script.sh

# First day of every month at midnight
0 0 1 * * /path/to/script.sh

# Every 15 minutes
*/15 * * * * /path/to/script.sh

# Every weekday (Mon-Fri) at 6 PM
0 18 * * 1-5 /path/to/script.sh

# Twice per day (8 AM and 8 PM)
0 8,20 * * * /path/to/script.sh
```

**Verify Crontab:**
```bash
crontab -l
```

**Expected Output:**
```
5 4 * * * /home/sysadmin/backuplog.sh
```

**Cron Logging:**
```bash
grep CRON /var/log/syslog
```

Shows when cron jobs run and their output.

**Troubleshooting Cron:**

**Issue 1: Script Not Running**
```
Solution:
- Use absolute paths in crontab (not ~/ or relative paths)
- Ensure script has execute permissions (chmod +x)
- Check cron logs: grep CRON /var/log/syslog
```

**Issue 2: Script Runs But Fails**
```
Solution:
- Add error redirection in crontab:
  5 4 * * * /home/sysadmin/backuplog.sh >> /tmp/backup.log 2>&1
- Check script has necessary permissions
- Verify all paths in script are absolute
```

**Issue 3: Environment Variables**
```
Problem: Cron runs in limited environment (PATH, HOME not set)
Solution: Set variables at top of crontab:
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  HOME=/home/sysadmin
  5 4 * * * /home/sysadmin/backuplog.sh
```

**Production Best Practices:**
1. **Redirect Output:**
   ```
   5 4 * * * /path/script.sh >> /var/log/backup.log 2>&1
   ```
2. **Email Notifications:**
   ```
   MAILTO=admin@example.com
   5 4 * * * /path/script.sh
   ```
3. **Locking (Prevent Concurrent Runs):**
   ```bash
   #!/bin/bash
   LOCKFILE=/var/run/backup.lock
   if [ -f ${LOCKFILE} ]; then
       echo "Backup already running"
       exit 1
   fi
   touch ${LOCKFILE}
   # ... backup commands ...
   rm ${LOCKFILE}
   ```
4. **Use anacron for laptops/desktops** (runs missed jobs when system powers on)

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Cross-Distribution Linux Administration**
   - Deployed Ubuntu (Debian-based) web server
   - Deployed Rocky Linux (RHEL-based) database server
   - Understood apt vs. yum package management
   - Navigated distribution-specific differences

2. **LAMP Stack Deployment**
   - Linux operating system
   - Apache web server
   - MySQL/MariaDB database
   - PHP scripting language
   - Complete web application infrastructure

3. **User & Group Management**
   - Created users with different methods (adduser, useradd)
   - Managed group memberships
   - Implemented role-based access control
   - Verified permissions with getent and groups

4. **Linux Security Hardening**
   - Enforced password aging policies
   - Implemented password complexity requirements
   - Configured automatic security updates
   - Managed sudo privileges with visudo
   - Applied file permission restrictions
   - Demonstrated principle of least privilege

5. **Automation & Scripting**
   - Wrote bash script for log backup
   - Scheduled recurring tasks with cron
   - Implemented log rotation and retention
   - Applied DevOps practices

6. **Network Security**
   - Configured firewall rules for server access
   - Implemented network segmentation
   - Applied defense-in-depth principles

### Linux Hardening Concepts

**CIS Benchmark Alignment:**
- ✅ Password complexity enforced
- ✅ Password aging implemented
- ✅ Automatic updates enabled
- ✅ sudo configured properly
- ✅ File permissions restricted
- ✅ Log management automated

**Security Controls Implemented:**
- Authentication (strong passwords)
- Authorization (sudo, file permissions)
- Accounting (log backups)
- Defense-in-depth (firewall + hardening)

---

## 🔐 Security Implications & Real-World Impact

### Enterprise Benefits

**1. Multi-Tier Architecture**
- Separation of concerns (web/database)
- Independent scaling
- Fault isolation
- Security segmentation

**2. Security Baseline**
- Password policies prevent weak credentials
- Automatic updates close vulnerabilities quickly
- File permissions prevent privilege escalation
- sudo logging enables audit trail

**3. Automated Operations**
- Reduced human error
- Consistent execution
- 24/7 operation without manual intervention
- Compliance with retention policies

### Attack Scenarios Mitigated

**Scenario 1: Brute Force Attack**
- Mitigation: Strong password requirements (10 chars, 2 digits, 1 uppercase)
- Result: Attack computationally infeasible

**Scenario 2: Privilege Escalation**
- Mitigation: Restricted file permissions, controlled sudo access
- Result: Attacker cannot gain root access from compromised user account

**Scenario 3: Data Loss**
- Mitigation: Automated log backups with retention
- Result: Forensic evidence preserved for incident investigation

**Scenario 4: Unpatched Vulnerability Exploitation**
- Mitigation: Automatic security updates (unattended-upgrades)
- Result: Critical vulnerabilities patched within 24 hours

### Compliance & Governance

**PCI-DSS:**
- Requirement 8.2.3: Strong passwords ✅
- Requirement 8.2.4: Password changes every 90 days ✅ (70 days)
- Requirement 10.7: Log retention 1 year ✅ (automated backups)

**HIPAA:**
- Access Control (§164.312(a)(1)) ✅ (sudo, file permissions)
- Audit Controls (§164.312(b)) ✅ (log management)

**SOX:**
- IT General Controls ✅ (automated processes)
- Change Management ✅ (sudo logging)

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Linux System Administrator ($75K-$110K):**
- Deploy and configure Linux servers
- Manage user accounts and permissions
- Implement security baselines
- Automate maintenance tasks
- Monitor and manage logs

**DevOps Engineer ($95K-$140K):**
- Automate infrastructure deployment
- Implement CI/CD pipelines
- Manage configuration with code
- Script repetitive tasks
- Infrastructure as Code (IaC)

**Security Engineer ($90K-$130K):**
- Harden Linux systems per CIS benchmarks
- Implement security controls
- Manage access control policies
- Monitor security logs
- Respond to incidents

**Site Reliability Engineer (SRE) ($110K-$160K):**
- Ensure system reliability and uptime
- Automate operational tasks
- Implement monitoring and alerting
- Manage incident response
- Capacity planning

### Enterprise Scenarios

**Scenario 1: E-Commerce Platform**
```
Challenge: Deploy scalable web infrastructure
Solution: 
- Multiple Ubuntu web servers (load balanced)
- Rocky DB servers (master-replica)
- Automated backups every 4 hours
- Security hardening per PCI-DSS
Result: 99.99% uptime, passed PCI audit
```

**Scenario 2: Healthcare Portal**
```
Challenge: HIPAA-compliant patient portal
Solution:
- Segregated networks (DMZ, app tier, data tier)
- Strong authentication (PAM + 2FA)
- Audit logging with 7-year retention
- Automatic security patching
Result: HIPAA compliant, protected patient data
```

**Scenario 3: Financial Services**
```
Challenge: SOX-compliant transaction processing
Solution:
- Immutable audit logs (write-once storage)
- Privileged access management (sudo logging)
- Change management (all changes logged)
- Automated compliance reporting
Result: Passed SOX audit, zero findings
```

---

## 📚 Commands Reference

### Package Management

**Ubuntu (apt):**
```bash
sudo apt update              # Update package index
sudo apt upgrade             # Install updates
sudo apt install    # Install package
sudo apt remove     # Remove package
sudo apt autoremove          # Remove unused dependencies
sudo apt search        # Search for packages
```

**Rocky Linux (yum/dnf):**
```bash
sudo yum update              # Update all packages
sudo yum install    # Install package
sudo yum remove     # Remove package
sudo yum search        # Search for packages
sudo yum list installed      # List installed packages
sudo dnf update              # dnf (modern yum)
```

### User & Group Management

```bash
# Create users
sudo adduser                     # Interactive (Debian)
sudo useradd -m -s /bin/bash    # Non-interactive (all)
sudo passwd                      # Set password

# Modify users
sudo usermod -aG         # Add to group
sudo usermod -l         # Rename user
sudo userdel -r                 # Delete user and home

# Group management
sudo groupadd                  # Create group
sudo groupdel                  # Delete group
getent group                   # List group members
groups                          # Show user's groups
id                              # Show UID/GID/groups
```

### File Permissions

```bash
# Change permissions
chmod 755              # rwxr-xr-x
chmod u+x              # Add execute for owner
chmod g-w              # Remove write for group
chmod o=               # Remove all for others

# Change ownership
chown user:group       # Change owner and group
chown user             # Change owner only
chgrp group            # Change group only

# Special permissions
chmod +t          # Sticky bit (only owner can delete)
chmod u+s              # SUID (run as owner)
chmod g+s         # SGID (inherit group)
```

### Service Management (systemd)

```bash
sudo systemctl start      # Start service
sudo systemctl stop       # Stop service
sudo systemctl restart    # Restart service
sudo systemctl enable     # Enable on boot
sudo systemctl disable    # Disable on boot
sudo systemctl status     # Check status
sudo systemctl list-units          # List all services
```

### Cron

```bash
crontab -e          # Edit user crontab
crontab -l          # List user crontab
crontab -r          # Remove user crontab
sudo crontab -u  -e   # Edit another user's crontab
```

### Log Management

```bash
# View logs
tail -f /var/log/syslog                  # Follow system log
tail -n 100 /var/log/auth.log            # Last 100 lines
grep "error" /var/log/apache2/error.log  # Search logs
journalctl -u apache2                    # systemd logs for service
journalctl -f                            # Follow all logs

# Compress logs
gzip /path/to/logfile                    # Compress with gzip
tar -czf backup.tar.gz /path/to/logs     # Archive and compress
```

---

## 💡 Lessons Learned

### Technical Insights

1. **Distribution Differences Matter**
   - Package managers differ (apt vs. yum)
   - Configuration file locations vary
   - Default security policies different
   - Cross-platform knowledge valuable

2. **Security is Layered**
   - Firewall + Hardening + Monitoring
   - Defense-in-depth principle
   - No single control is sufficient

3. **Automation Reduces Human Error**
   - Cron ensures tasks run consistently
   - Scripts are repeatable and testable
   - Reduces operational overhead

4. **Password Policies Must Be Balanced**
   - Too strict: Users write passwords down
   - Too lax: Easy to compromise
   - Find business-appropriate balance

5. **Logs Are Critical for Security**
   - Incident investigation requires logs
   - Retention policies prevent evidence loss
   - Automated backup ensures availability

### Professional Practices

1. **Always Test Changes in Lab First**
   - Never run untested commands in production
   - Validate scripts before scheduling with cron
   - Document testing procedures

2. **Use visudo for sudoers**
   - Syntax checking prevents lockout
   - Critical for maintaining access

3. **Schedule Maintenance During Low-Traffic Windows**
   - 4 AM is standard maintenance window
   - Minimize user impact
   - Coordinate with stakeholders

4. **Document Everything**
   - Configuration changes
   - Hardening steps taken
   - Automation implemented
   - Future administrators will thank you

---

## 🔗 Related Technologies

### Web Server Alternatives
- **Nginx** - High-performance, lightweight alternative to Apache
- **Caddy** - Automatic HTTPS with Let's Encrypt
- **LiteSpeed** - Drop-in Apache replacement with better performance

### Database Alternatives
- **PostgreSQL** - Advanced open-source database
- **MySQL** - Original MySQL (Oracle-owned)
- **MongoDB** - NoSQL document database

### Configuration Management
- **Ansible** - Agentless automation and orchestration
- **Puppet** - Configuration management at scale
- **Chef** - Infrastructure as Code
- **SaltStack** - Event-driven automation

### Monitoring & Logging
- **Prometheus** - Metrics collection and alerting
- **Grafana** - Visualization and dashboards
- **ELK Stack** - Elasticsearch, Logstash, Kibana (log aggregation)
- **Graylog** - Centralized log management

### Security Scanning
- **Lynis** - Security auditing tool for Linux
- **OpenSCAP** - Security compliance checking
- **ClamAV** - Antivirus for Linux
- **AIDE** - File integrity monitoring

### Industry Certifications

**Linux Administration:**
- **RHCSA** - Red Hat Certified System Administrator
- **RHCE** - Red Hat Certified Engineer
- **LPIC-1/2/3** - Linux Professional Institute Certification
- **CompTIA Linux+** - Vendor-neutral Linux certification

**Security:**
- **GIAC GCUX** - Unix Security Administrator
- **CompTIA Security+** - Includes Linux security
- **CISSP** - Includes Unix/Linux security domain

---

## 📸 Lab Evidence

All screenshots documented in original lab report:

**Firewall Configuration:**
- ✅ AdminNet firewall rules
- ✅ ServerNet firewall rules (6 new rules)

**Ubuntu Web Server:**
- ✅ Network configuration (ip r)
- ✅ Connectivity tests (ping 8.8.8.8)
- ✅ System updates (apt update)
- ✅ VMware Tools installation
- ✅ Apache2 and PHP stack installation

**Rocky DB Server:**
- ✅ Network configuration
- ✅ System updates (yum update)
- ✅ VMware Tools installation
- ✅ MariaDB installation

**User & Group Management:**
- ✅ User creation (adduser, useradd)
- ✅ Group creation (UBNetDef, BlackTeam, SysSec)
- ✅ Group membership verification

**Security Hardening:**
- ✅ Password aging policy (/etc/login.defs)
- ✅ Automatic security updates
- ✅ sudo configuration (visudo)
- ✅ File permission restrictions
- ✅ Password quality requirements

**Automation:**
- ✅ Log backup script creation
- ✅ Script permissions (chmod +x)
- ✅ Cron job scheduling
- ✅ Crontab verification

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**Servers Deployed:** ✅ Ubuntu Web + Rocky DB  
**Security Hardening:** ✅ 6 controls implemented  
**Automation:** ✅ Cron job scheduled  
**Users/Groups:** ✅ 5 users, 3 groups created  
**Firewall Rules:** ✅ 7 new rules (AdminNet + ServerNet)

---

## 🔍 Troubleshooting Guide

### Common Issues

**Issue 1: Package Installation Fails**
```
Symptoms: "Unable to locate package" or dependency errors
Solution:
- sudo apt update (refresh package index)
- Check internet connectivity
- Verify repository configuration in /etc/apt/sources.list
- Try alternative mirror
```

**Issue 2: Permission Denied Errors**
```
Symptoms: Cannot edit files, run commands
Solution:
- Check file ownership: ls -l <file>
- Use sudo for system files
- Verify user in correct group: groups <username>
- Check file permissions: chmod appropriately
```

**Issue 3: Cron Job Not Running**
```
Symptoms: Script not executing at scheduled time
Solution:
- Check crontab syntax: crontab -l
- Use absolute paths in crontab
- Verify script has execute permission
- Check cron logs: grep CRON /var/log/syslog
- Redirect output for debugging:
  5 4 * * * /path/script.sh >> /tmp/cron.log 2>&1
```

**Issue 4: Apache Not Starting**
```
Symptoms: systemctl status apache2 shows failed
Solution:
- Check error logs: sudo tail /var/log/apache2/error.log
- Verify port 80/443 not in use: sudo netstat -tlnp
- Test configuration: sudo apache2ctl configtest
- Check firewall: sudo ufw status
```

**Issue 5: MariaDB Access Denied**
```
Symptoms: ERROR 1045: Access denied for user
Solution:
- Reset root password: sudo mysql_secure_installation
- Check user privileges: SHOW GRANTS FOR 'user'@'host';
- Verify bind-address in /etc/mysql/mariadb.conf.d/50-server.cnf
- Check firewall allows MySQL port 3306
```

---
