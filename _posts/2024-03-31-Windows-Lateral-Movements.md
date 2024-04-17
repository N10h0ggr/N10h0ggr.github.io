---
title: Windows Lateral Movements
date: 2024-03-31
categories:
  - red-team
  - windows
tags:
  - english
toc: "true"
---

This post or notes will explain, more or less extensively, how to execute lateral movements between users or systems.

# Authentication

Primarily, there are two ways to authenticate: NTLM and Kerberos, although there are also other methods.

These authentications can be classified into two groups:

- **Active or Physical Authentication**: The user inputs their credentials directly on the host where they want to log in. This type of authentication does not require any special privileges.
- **Passive or Remote Authentication**: The user logs in from another device, either through SSH, RDP, or any other type of authentication that doesn't require being physically in front of the machine. This type of authentication requires some special privileges in their identity.

Note that this applies to both local authentications (authentication via SAM) and authentications via AD (via NTDS). Logging in to a remote server as .\user also requires privileges not provided by default. Logging in as Corp\DomainUser1 physically from a workstation does not require special privileges; it is possible with the default account. Another matter is if a whitelist has been applied to that workstation.

Authentication Packages

As mentioned earlier, there are two types of predominant authentications. Each of these uses a different DLL and its own flow.

Local authentication by Msv1_0 (NTLM):

1. The user sends a request to the SAM of hostA (e.g., hostA\attl4s).
2. HostA sends a challenge.
3. The user signs that challenge with their NTLM hash.
4. The system confirms the signature through SAM.

For AD, NTML along with Kerberos can also be used and is likely utilized. For the explanation of Kerberos, there is another set of notes.

Note: Groups from AD and specific users from AD can be added as local administrators of a specific system.

Note: The Domain Admins group is always set as local administrators of all machines due to one or two policies that are activated by default in the DC.

The authentication flow can be summarized as follows:

1. The user authenticates on a system, either physically or remotely.
2. The authentication package (be it Kerberos, NTLM, or other) creates a Logon Session; it combines the ID of that Logon Session with security information (identifiers, privileges, etc.) and passes it to the Local Security Authorization (LSASs).
3. LSAS creates a Token.

# Logon Sessions

A logon session is an entity created when authentication is successful.

IMPORTANT: All credentials stored in memory are ALWAYS linked to a Logon Session.

There are two types of logon sessions:

- Interactive (not over the network)
- Non-interactive (remote)

Logon sessions differ depending on the user's privilege levels (also called integrity levels). Medium integrity processes are those running with normal user privileges, and high integrity processes are all those running as administrators. This differentiation requires creating two separate logon sessions for the same user.

Note: Since Kerberos does not work with IPs, when you access a shared system folder (such as \10.10.10.10\C$), a non-interactive logon session authenticated by NTLM is created. Note that this logon session is created on the 10.10.10.10 system. If you use the hostname or SPN instead of the IP, the authentication will be via Kerberos.

Important: Interactive logon sessions are stored in memory in the lsass.exe process to implement SSO.

Authentication for non-interactive sessions works in such a way that the user has to prove they have those credentials without sending them over the network. This way, the credentials are not stored in memory. Unless Kerberos delegation or specific options for certain types of authentication are used.

Important: Having non-interactive access to a system does not imply that we can access all resources of that system. Let me explain: we get a remote shell as a system administrator on host01. Since it's a non-interactive session, the credentials are not stored in memory. Since the credentials are not stored in memory, SSO is not implemented, so for any action on a remote host that requires authentication (for example, listing a shared folder), we will have to provide the credentials. If these credentials were in memory, we wouldn't have to specify them.

LSA is responsible for creating tokens to access resources and applications locally. Each token is linked to a logon session.

Every process/thread has a Token referencing a logon session, which may or may not have credentials.

# Access Tokens

Access tokens are data structures containing information about the identity and privileges associated with a user account.

Every process executed on behalf of a user has a copy of the token. A user can have several tokens, one for each "execution context."

Access tokens are used by Windows to implement access controls. Within Windows Security Descriptors of a specific object (e.g., a file), there's an attribute called the Discretionary Access Control List (DACL) containing a series of rules that define who has access to that specific resource and who doesn't. Access tokens are used by processes or threads to present an identifier to the operating system. The OS then checks if the User SID or groups are in the DACL of the resource or object and what permissions they have on it.

## Types of Tokens

Two types of tokens can be differentiated:

### Primary Tokens (Process Tokens)

Each process has an associated primary token. By default, it inherits the token from its parent process.

### Impersonation Tokens (Thread Tokens)

Allow threads to run in a different security context than the originating process. They are typically used in client/server scenarios (service accounts).

For example, a database usually runs under a service account. The database process has a main thread associated with it, inheriting its Primary Token. However, when a user (e.g., User B) connects to the database, a new thread is generated, and that thread is created with an Impersonation Token representing User B, impersonating them. This way, when User B tries to access certain tables in the database, access controls can be applied.

Generally, service accounts come with the SeImpersonatePrivilege and SeAssignPrimaryPrivilege privileges so that when a user connects to a service, it can create an Access Token impersonating them. This is what the RottenPottato vulnerability abuses.

Within impersonation tokens, there are four levels depending on the information within the token. We are only interested in tokens that fully impersonate the user (also called Delegation Tokens).

Delegation Tokens refer to an interactive Logon Session, so they have credentials in memory and can therefore be used to access remote resources.

# User Impersonation

Impersonation is the ability of a thread to run in a different security context from the security context of the process it belongs to.

At this point, from an attacker's perspective, we can ask three questions.

## Do I have passwords?

Let's imagine we have found a password in a shared file. At this point, several things can be done.

The first one is to use runas.exe. Runas.exe is useful for lateral movements by executing commands as other users. If you enter a machine as the user Pepe and have Jesus' credentials, you can execute commands as Jesus. This is valid whether Jesus is a local user of the system or a domain user; the important thing is that they have access to the system.

By default, runas executes commands locally. To run commands remotely, it is necessary to use the /netonly flag. For example, consider this command:

bash

`runas /user:capsule.corp\vegeta /netonly cmd`

This command will prompt us for the credentials of the domain user vegeta and will open a cmd. This cmd is opened locally but with the peculiarity that if we try to interact with a remote resource or system, it will use the credentials we provided earlier to authenticate. It is important to note that our system will not check if the credentials are correct; that is up to the remote system. Therefore, the logon session created when using the /netonly flag will not match the access token of the runas process.

When running runas with this flag, Windows creates a new logon session with the credentials we have indicated. Then it clones the access token of the process that ran runas and modifies it to refer to the new logon session. Finally, it creates a new process (in this case, cmd) and assigns that access token to it.

Runas prompts for credentials interactively, making it impossible to use via a reverse shell. Also, the use of runas may be logged in the system's logs and events.

The vast majority of C2 frameworks have their own implementation of runas through the Win32 API.

This executable creates an access token similar to the one created with an interactive logon, meaning that it stores the credentials in memory to implement SSO.

## What if I have a HASH?

### Pass the hash in Windows

The steps are almost the same as those used by runas:

1. Create a new logon session.
2. Modify the hash of that new logon session (admin permissions are required).
3. Copy the original token and make it refer to the new logon session.
4. Use that token.

It's like runas /netonly but with the hash instead of the password.

In a normal procedure, a user would provide their credentials, and LSASS would create the NTLM hash to guarantee access to the host. By using Pass the Hash, you inject that hash directly into LSASS.

Note: mimikatz implements both pass the hash and over-pass the hash: once the NTLM hash is written into LSASS, it takes advantage of it for Windows to request TGS tickets.

### Pass the ticket

It's the same as pass the hash but with TGT tickets. The Kerberos library allows us to import tickets without needing to be administrators.

Important: these types of attacks can be identified if logon sessions containing tokens or tickets that do not belong to the same owner as that logon session are found.

#### ASK-TGT/TGS

It generates legitimate Kerberos traffic without the need for Windows to intervene, so it doesn't require being an administrator.

## What about tokens?

In the end, all the previous steps are necessary if we don't already have a token that interests us. A process that may interest us can be any process with an interactive session of a domain administrator. Remember that for the token to have credentials in memory, it must be associated with an interactive logon session.

Manipulating tokens actions require local administrator permissions.

### Token impersonation/theft

Basically, it consists of duplicating a token (that interests us) referring to a logon session with credentials. Then we assign this token to a new process or to a thread of a process that interests us. This can be achieved through the Win32 API.

### Injecting tokens with context

This second technique consists of injecting yourself into the context where the token you are interested in is. It involves injecting payload (which can be a DLL) into the process to which the token we are interested in is assigned. It can also be process hollowing, etc.