# Active Directory Orphaned SID Auditor

A PowerShell utility for auditing unresolved security identifiers (SIDs) in Active Directory object access control lists (ACLs).

## Features

- Scans Active Directory objects within a specified search base.
- Identifies candidate orphaned domain-account SIDs.
- Reports explicit and inherited access control entries (ACEs).
- Exports findings to CSV for review and audit documentation.
- Supports previewing proposed changes with `-WhatIf`.

## Requirements

- Windows PowerShell
- Active Directory PowerShell module
- Network connectivity to Active Directory
- Appropriate permissions to read ACLs and, when remediating, modify them

## Usage

Audit only:

```powershell
.\Repair-ADOrphanedSIDs.ps1
```

Preview potential removals:

```powershell
.\Repair-ADOrphanedSIDs.ps1 -Remove -WhatIf
```

Audit a specific OU:

```powershell
.\Repair-ADOrphanedSIDs.ps1 -SearchBase "OU=Test,DC=example,DC=com"
```

## Safety and limitations

An unresolved SID is not conclusive proof of an obsolete account. Trust failures, unavailable domain controllers, and migrations can cause resolution failures.

Inherited ACEs should be traced to the ancestor ACL where the permission originates. Removing an ACE can affect access for many descendant objects.

Test in a non-production environment, review the CSV report, and back up relevant security descriptors before remediation.

The current implementation is a starting point and should be validated before production use. It does not automatically prove that every unresolved SID is safe to remove.

## License

No license has been selected. All rights are reserved unless a license is added to this repository.
