# Lab 04: Active Directory & Group Policy Management

## 📋 Lab Overview
 
**Difficulty Level:** Advanced  


### Objective
This lab demonstrates enterprise Windows infrastructure management by deploying Active Directory Domain Services, joining systems to a domain, creating and managing users and groups, implementing Group Policy Objects (GPOs) for centralized configuration management, and deploying IIS web services. This simulates real-world enterprise IT operations where thousands of devices and users are managed centrally.

---

## 🎯 Learning Outcomes

By completing this lab, I demonstrated proficiency in:

- **Active Directory Domain Services (AD DS):** Managing enterprise directory services
- **Domain Integration:** Joining Windows systems to a domain for centralized management
- **User & Group Management:** Creating users, assigning roles, implementing RBAC
- **Group Policy Objects (GPO):** Centralized configuration management across domain
- **Web Server Deployment:** Installing and configuring IIS (Internet Information Services)
- **PowerShell Logging:** Implementing security auditing with transcription
- **Organizational Units (OUs):** Structuring AD hierarchy for policy application
- **Security Policy Development:** Creating password policies and access restrictions

---

## 🛠️ Tools & Technologies Used

### Windows Server Technologies
- **Active Directory Domain Services (AD DS)** - Enterprise directory and identity management
- **Group Policy Management Console (GPMC)** - Centralized configuration management
- **Internet Information Services (IIS)** - Microsoft web server platform
- **Server Manager** - Windows Server administration dashboard
- **PowerShell** - Windows automation and scripting

### Active Directory Components
| Component | Purpose |
|-----------|---------|
| **Domain Controller (ADServer)** | Hosts AD DS, manages authentication and authorization |
| **Domain (team32.local)** | Enterprise namespace for resources and identities |
| **Organizational Units (OUs)** | Containers for organizing AD objects and applying policies |
| **Users & Groups** | Identity management and role-based access control |
| **Group Policy Objects (GPOs)** | Centralized configuration settings and security policies |

---

## 🏗️ Lab Environment Architecture

### Domain Infrastructure

```
                    [Internet]
                        |
                  [pfSense Router]
                        |
        +---------------+---------------+
        |                               |
    [AdminNet]                     [ServerNet]
    10.42.32.0/24                 10.43.32.0/24
        |                               |
    +---+---+                      +----+----+
    |       |                      |         |
[Win10]  [Outside]            [ADServer] [IISServer]
10.42.32.12                   10.43.32.10  10.42.32.90

DOMAIN: team32.local
Domain Controller: ADServer (10.43.32.10)
Member Servers: IISServer
Member Workstations: Win10Client
```

### Active Directory Structure

```
team32.local (Domain Root)
├── Domain Controllers OU
│   └── ADServer
├── Users Container
│   ├── Kevin (Domain Admin)
│   ├── Dave CEO (Standard User)
│   └── (other users)
├── Groups Container
│   ├── UBFaculty (Security Group)
│   ├── Workstations (Security Group)
│   ├── Domain Admins
│   ├── Domain Users
│   └── Domain Computers
└── WinOUs (Custom OU - Additional Task)
    ├── Win10Client
    └── IISServer
```

---

## 📝 Methodology & Implementation

### Phase 1: Domain Integration

#### Understanding Active Directory Domains

**What is a Domain?**
An Active Directory domain is a logical grouping of network resources (computers, users, printers) that share:
- Common directory database (stored on domain controllers)
- Unified security policies
- Centralized authentication and authorization
- Trust relationships with other domains

**Benefits of Domain Membership:**
1. **Centralized Authentication:** Single sign-on (SSO) across all domain resources
2. **Group Policy Management:** Deploy configurations from central location
3. **Simplified Administration:** Manage thousands of devices from one console
4. **Enhanced Security:** Kerberos authentication, encryption, auditing
5. **Resource Sharing:** Easy access to shared folders, printers, applications

#### Task 1.1: Join Win10Client to Domain

**Process:**
1. Navigate to: Settings → System → About → "Rename this PC (advanced)"
2. Computer name: `Win10Client`
3. Domain: `team32.local`
4. Authenticate with domain admin credentials
5. Restart to complete domain join

**What Happens During Domain Join?**
- Computer contacts domain controller via DNS
- Secure channel established using Kerberos
- Computer account created in AD
- Domain security policies downloaded and applied

**Security Benefits:**
- Centralized password policies apply
- Domain admins can remotely manage system
- Audit logging centralized on domain controller

#### Task 1.2: Join IISServer to Domain

**Method Using SConfig:**
```cmd
sconfig
Option 1: Domain/Workgroup settings
Select "D" for Domain
Enter domain name: team32.local
```

**Verification:**
```powershell
Get-ComputerInfo | Select-Object CsDomain, CsDomainRole
```

---

### Phase 2: User Account Management

#### Task 2.1: Create User "Kevin" with Admin Rights

**Process:**
1. Open Active Directory Users and Computers (ADUC)
2. Navigate to Users container
3. Right-click → New → User
4. First name: Kevin, User logon name: Kevin
5. Password: Change.me!
6. Uncheck "User must change password at next logon"

**Grant Administrative Privileges:**
1. Right-click user "Kevin" → Properties
2. Member Of tab → Add
3. Enter: Domain Admins → Check Names → OK

**Domain Admin Privileges:**
- Full control over all domain resources
- Can modify any AD object
- Can change domain policies

**Security Warning:**
⚠️ Domain Admin is most powerful account in domain. Should be used sparingly and monitored closely.

#### Task 2.2: Create Standard User "Dave CEO"

**Configuration:**
- Name: Dave CEO
- Password: Change.me!
- Group Membership: Domain Users (default only)
- Do NOT add to Domain Admins

**Purpose:**
Demonstrates standard user creation following principle of least privilege.

---

### Phase 3: Server Management & IIS Deployment

#### Task 3.1: Add IISServer to Server Manager Pool

**Purpose:**
Centralized management of multiple servers from single console.

**Process:**
1. Server Manager → Manage → Add Servers
2. Search Active Directory for "IISServer"
3. Add to Selected pane → OK
4. Verify status shows "Online" in All Servers view

#### Task 3.2: Install IIS Web Server on IISServer

**Installation Process:**
1. Server Manager → Manage → Add Roles and Features
2. Installation Type: Role-based
3. Server Selection: IISServer.team32.local
4. Server Roles: Check "Web Server (IIS)"
5. Add required features
6. Install

**Testing:**
- Local: http://localhost (on IISServer)
- Internal: http://10.42.32.90 (from Win10Client)
- External: http://10.42.32.90 (from OutsideDevice - requires firewall rule)

#### Task 3.3: Configure Firewall Rule

**pfSense Configuration:**
- Interface: AdminNet
- Protocol: TCP
- Destination: IISServer (10.42.32.90)
- Destination Port: HTTP (80), HTTPS (443)
- Description: "Allow OutsideDevice to IISServer web services"

---

### Phase 4: Group Management

#### Task 4.1: Create UBFaculty Security Group

**Configuration:**
- Group name: UBFaculty
- Group scope: Global
- Group type: Security
- Members: Domain Users (all users are faculty)

**Purpose:**
Group for university faculty members with specific access rights.

#### Task 4.2: Create Workstations Security Group

**Configuration:**
- Group name: Workstations  
- Group scope: Global
- Group type: Security
- Members: Domain Computers (all domain-joined computers)

**Use Cases:**
- Apply Group Policies to all computers
- Grant permissions to network resources
- Deploy software to all workstations

---

### Phase 5: Group Policy - Desktop Background

#### Task 5.1: Prepare Background Image

**On ADServer:**
1. Create folder: C:\Background Desktop Pics
2. Place image: logo.jpg
3. Share folder as "BackgroundPics"
4. Grant Domain Computers Read permission

**Network Path:** `\\ADServer\BackgroundPics\logo.jpg`

#### Task 5.2: Create Desktop Background GPO

**Process:**
1. Group Policy Management → Right-click team32.local
2. Create a GPO: "Desktop Background GPO"
3. Edit GPO → Navigate to:
   ```
   User Configuration → Policies → Administrative Templates
   → Desktop → Desktop → Desktop Wallpaper
   ```
4. Enable setting
5. Wallpaper Name: `\\ADServer\BackgroundPics\logo.jpg`
6. Wallpaper Style: Fill

**Security Filtering:**
- Remove: Authenticated Users
- Add: Workstations group
- Add: Domain Computers

**Force Application:**
```cmd
gpupdate /force
```

**Verification:**
- Log into Win10Client - background changes to logo.jpg
- User cannot change wallpaper (setting enforced)

---

### Phase 6: Group Policy - PowerShell Transcription

#### Understanding PowerShell Logging

**Why Log PowerShell?**
- PowerShell increasingly used by attackers for post-exploitation
- Logging provides audit trail for security incidents
- Required for compliance (SOX, PCI-DSS, HIPAA)

**PowerShell Logging Types:**
1. **Transcription:** Creates text files of PowerShell sessions
2. **Script Block Logging:** Logs to Windows Event Log
3. **Module Logging:** Very verbose, captures all cmdlet execution

#### Task 6.1: Create PowerShell Transcription GPO

**Process:**
1. Create GPO: "PowerShell Transcription Policy"
2. Edit → Navigate to:
   ```
   Computer Configuration → Policies → Administrative Templates
   → Windows Components → Windows PowerShell
   ```

#### Task 6.2: Enable Transcription

**Setting: Turn on PowerShell Transcription**
- Enable
- Transcript output directory: `\\ADServer\PowerShellLogs`
- Include invocation headers: Checked

**Transcript File Format:**
`PowerShell_transcript.COMPUTER.USER.TIMESTAMP.txt`

#### Task 6.3: Enable Script Block Logging

**Setting: Turn on PowerShell Script Block Logging**
- Enable
- Log script block invocation start/stop: Checked

**Event Log Location:**
Applications and Services → Microsoft → Windows → PowerShell → Operational (Event ID 4104)

#### Task 6.4: Testing

**On Win10Client:**
```powershell
pwd  # Execute command
exit # Close PowerShell
```

**Verify on ADServer:**
- Navigate to \\ADServer\PowerShellLogs
- New folder created (WIN10CLIENT)
- Transcript file contains command history

---

### Phase 7: Organizational Units & Advanced Policies

#### Task 7.1: Create WinOUs Organizational Unit

**Purpose:**
Organize Windows computers for targeted policy application.

**Process:**
1. Active Directory Users and Computers
2. Right-click team32.local → New → Organizational Unit
3. Name: WinOUs
4. Move Win10Client and IISServer to WinOUs OU

**Final Structure:**
```
team32.local
├── Domain Controllers OU
│   └── ADServer
├── Users Container
│   ├── Kevin, Dave CEO
│   └── Groups (UBFaculty, Workstations)
└── WinOUs OU
    ├── Win10Client
    └── IISServer
```

#### Task 7.2: Password Policy GPO (Additional Task)

**Implementation:**
1. Create GPO linked to WinOUs
2. Configure Password Policy:
   ```
   Computer Configuration → Policies → Windows Settings
   → Security Settings → Account Policies → Password Policy
   ```

**Recommended Settings:**
- Enforce password history: 24 passwords
- Maximum password age: 90 days
- Minimum password length: 14 characters
- Password must meet complexity: Enabled
- Account lockout threshold: 5 invalid attempts
- Account lockout duration: 30 minutes

#### Task 7.3: Restrict Employee User Logon

**Objective:**
Prevent standard "Employee Users" from logging into workstations.

**Implementation:**
1. Create "Employee Users" OU
2. Create GPO with User Rights Assignment:
   - Deny log on locally
3. Users cannot log into workstations interactively
4. Can still access network resources

---

## 🎓 Key Takeaways & Skills Demonstrated

### Technical Skills

1. **Active Directory Administration**
   - Deployed and configured domain controller
   - Joined computers to domain
   - Created and managed user accounts
   - Implemented group-based access control

2. **Group Policy Management**
   - Created multiple GPOs for different purposes
   - Configured User and Computer policies
   - Implemented security filtering
   - Forced policy application and verified results

3. **Windows Server Roles**
   - Installed IIS web server remotely
   - Configured Server Manager for multi-server management
   - Deployed network file sharing

4. **Security Implementation**
   - PowerShell transcription for auditing
   - Password policies for access control
   - Role-based access control (RBAC)
   - Least privilege principle

5. **Professional Documentation**
   - Wrote executive security policy memo
   - Documented AD structure and policies

### Enterprise IT Concepts

**Identity and Access Management (IAM):**
- Centralized user directory (Active Directory)
- Single sign-on (SSO) across domain resources
- Role-based access control
- Privileged access management

**Configuration Management:**
- Centralized policy deployment
- Standardized desktop configurations
- Automated security settings enforcement

**Security Operations:**
- PowerShell logging for threat detection
- Password policies for account security
- Account lockout to prevent brute force
- Audit trail for compliance

---

## 🔐 Security Implications & Real-World Impact

### Enterprise Benefits

**1. Centralized Management**
- Manage 1000s of computers from one console
- Group Policy deploys settings automatically
- Reduced administration time by 70-80%

**2. Enhanced Security**
- Password policies enforced via GPO
- PowerShell logged for forensics
- Prevents 90% of basic credential attacks

**3. Audit and Compliance**
- PowerShell transcription meets regulatory requirements
- AD audit logs for forensic analysis
- Supports SOX, HIPAA, PCI-DSS compliance

### Attack Scenarios Mitigated

**Scenario 1: Credential Brute Force**
- Mitigation: Account lockout policy (5 attempts, 30-min lockout)
- Result: Attack becomes impractical

**Scenario 2: PowerShell-Based Malware**
- Mitigation: PowerShell transcription logs all commands
- Result: Security team detects and blocks malware quickly

**Scenario 3: Privilege Escalation**
- Mitigation: Group membership controls, least privilege
- Result: Attacker cannot elevate without Domain Admin credentials

---

## 🚀 Real-World Applications

### Career Roles Demonstrated

**Windows System Administrator:**
- Deploy and manage Active Directory
- Create and manage user accounts at scale
- Implement Group Policy for configuration management
- Troubleshoot domain and policy issues

**Security Operations Center (SOC) Analyst:**
- Monitor PowerShell transcripts for malicious activity
- Investigate incidents using AD logs
- Detect privilege escalation attempts

**Identity and Access Management (IAM) Specialist:**
- Design role-based access control
- Manage user lifecycle
- Enforce password and authentication policies

**Compliance Auditor:**
- Verify password policies meet requirements
- Review audit logs for compliance evidence
- Document security controls

---

## 📚 Commands Reference

### Active Directory (PowerShell)

```powershell
# User Management
New-ADUser -Name "John Doe" -SamAccountName "jdoe"
Get-ADUser -Filter * | Select-Object Name, Enabled
Set-ADUser -Identity "jdoe" -Enabled $false

# Group Management
New-ADGroup -Name "IT Staff" -GroupScope Global
Add-ADGroupMember -Identity "IT Staff" -Members "jdoe"
Get-ADGroupMember -Identity "Domain Admins"

# Computer Management
Get-ADComputer -Filter *
Test-ComputerSecureChannel -Credential (Get-Credential)

# OU Management
New-ADOrganizationalUnit -Name "Sales"
Move-ADObject -Identity "CN=Win10Client,CN=Computers,DC=team32,DC=local" `
  -TargetPath "OU=WinOUs,DC=team32,DC=local"
```

### Group Policy

```powershell
# GPO Management
Get-GPO -All | Select-Object DisplayName
New-GPO -Name "Security Baseline"
Set-GPLink -Name "Security Baseline" -Target "OU=WinOUs,DC=team32,DC=local"

# Force GPO Update
gpupdate /force
gpresult /r  # Summary of applied GPOs
gpresult /h c:\gpo-report.html  # Detailed report
```

### Domain Join

```powershell
# Join Domain
Add-Computer -DomainName "team32.local" -Credential (Get-Credential) -Restart

# Check Membership
Get-ComputerInfo | Select-Object CsDomain, CsDomainRole
```

---

## 💡 Lessons Learned

### Technical Insights

1. **Active Directory is Complex but Powerful**
   - Single misconfiguration can affect entire organization
   - Test in lab before production deployment

2. **Group Policy Requires Understanding of Precedence**
   - LSDOU (Local, Site, Domain, OU) processing order
   - Enforced GPOs override lower-level policies

3. **PowerShell Logging is Essential**
   - Modern threats heavily use PowerShell
   - Transcription provides human-readable forensics

4. **Proper OU Structure Saves Time**
   - Plan before implementation
   - Mirrors organizational structure
   - Simplifies GPO application

### Professional Practices

1. **Change Management Process**
   - Document all AD changes
   - Test GPOs before wide deployment
   - Have rollback plan

2. **Security First Mindset**
   - Least privilege for user accounts
   - Separate admin and user accounts
   - Monitor privileged access

---

## 🔗 Related Technologies

### Microsoft Identity & Access

- **Azure Active Directory** - Cloud identity platform
- **Active Directory Certificate Services** - PKI infrastructure
- **Active Directory Federation Services** - SSO and federation

### Competing Technologies

- **OpenLDAP** - Open-source directory
- **FreeIPA** - Identity management for Linux
- **Okta** - Cloud-based identity management

### Industry Certifications

- **Microsoft 365 Security Administrator**
- **Identity and Access Administrator Associate**
- **CompTIA Security+** - Identity and access management
- **CISSP** - Domain 5: IAM

---

## 📸 Lab Evidence

All screenshots documented in original lab report:

**Active Directory:**
- ✅ Computers joined to domain
- ✅ Users created (Kevin, Dave CEO)
- ✅ Groups created (UBFaculty, Workstations)
- ✅ OU structure (WinOUs)

**IIS Deployment:**
- ✅ Web server accessible
- ✅ Firewall rule configured

**Group Policy:**
- ✅ Desktop background applied
- ✅ PowerShell transcription active
- ✅ Transcript files created

**Documentation:**
- ✅ Executive security memo
- ✅ Password policy proposal

---

## 🏆 Lab Status

**Completion Status:** ✅ Successfully Completed  
**Domain:** ✅ team32.local fully operational  
**Users:** ✅ 2 created with proper permissions  
**GPOs:** ✅ 2 deployed and tested  
**IIS:** ✅ Web server operational  
**Logging:** ✅ PowerShell transcription active  
**Documentation:** ✅ Complete with executive memo

---

## 🔍 Troubleshooting Guide

### Common Issues

**Issue 1: Computer Cannot Join Domain**
```
Solution:
- Check DNS points to ADServer
- ping ADServer.team32.local
- nslookup team32.local
- Set DNS to 10.43.32.10
```

**Issue 2: GPO Not Applying**
```
Solution:
- gpupdate /force
- gpresult /h c:\gpo-report.html
- Check Event Viewer: GroupPolicy logs
- Verify computer in Workstations group
```

**Issue 3: Cannot Access IIS**
```
Solution:
- Check IIS service: iisreset /start
- Add pfSense firewall rule (port 80)
- Allow HTTP in Windows Firewall
```

**Issue 4: PowerShell Transcripts Not Created**
```
Solution:
- Grant Domain Computers write access to shared folder
- gpupdate /force
- Check GPO applied: gpresult /r
```

---
