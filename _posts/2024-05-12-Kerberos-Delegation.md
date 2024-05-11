---
title: Kerberos Delegation
date: 2024-04-25
categories:
  - red-team
  - AD
tags:
  - english
toc: "true"
---


## What is Kerberos Delegation?
Kerberos delegation allows a service, like a web server, to obtain tickets on behalf of a user to access other services. It extends the user's authentication context to backend services, enabling seamless access without requiring the user's credentials to be transmitted. This mechanism ensures secure delegation of authentication and authorization, facilitating controlled access to resources.
## Why we need it?
Consider a scenario where you have a web application that utilizes Kerberos authentication for users to log in. Each user has their own set of data stored in a SQL database. Now, when a user logs in, the web server authenticates them via Kerberos. However, the web server faces a challenge: it needs to access the user's data from the SQL database. 

The problem arises because the web server, having authenticated the user, can't directly authenticate to the SQL database as that user. Traditional Kerberos authentication mechanisms don't provide a straightforward way for the web server to seamlessly act on behalf of the authenticated user to access their specific data in the SQL database. This is why Kerberos Delegation is created: the authentication flow from the web server to the SQL database lacks the necessary continuity to ensure that the user can only access their own data.

## How it works?
Kerberos delegation essentially extends the authentication context of the user to backend services like the SQL database. Traditionally, without delegation, the web server wouldn't have the necessary credentials to authenticate itself to the SQL database as the authenticated user.

Kerberos delegation resolves this issue by allowing the web server to obtain a service ticket from the KDC for the SQL service on behalf of the authenticated user. This service ticket contains the user's identity and grants the web server permission to access the SQL database using that identity.

With the obtained service ticket, the web server can securely communicate with the SQL database, presenting the user's identity as part of the authentication process. This enables the SQL server to trust the web server's identity, backed by Kerberos authentication.

Subsequently, the web server can retrieve the user's data from the SQL database and present it to the user through the web application. This entire process seamlessly extends the user's authentication context to backend services, ensuring that the user can only access their own data. 

## Types of Delegations

There are three ways to achieve Kerberos Delegation:

1. **Unconstrained Delegation**: This type allows a service to impersonate any user and access any service within the domain. While providing greater flexibility, it poses higher security risks, potentially enabling unauthorized access if compromised.
    
2. **Constrained Delegation**: Also known as S4U (Service-for-User) delegation, it permits a service to act on behalf of a user for a specific set of services. This limits the scope of delegation, enhancing security by reducing the risk of misuse.
    
3. **Resource-Based Delegation**: Resource-based delegation allows a service to delegate authentication requests based on the requested resource rather than the user's identity. It enhances security by ensuring that delegation occurs only when accessing specific resources, providing a more fine-grained control mechanism within Kerberos-enabled environments.

### Unconstrained Delegation

When a user authenticates to a service using Kerberos, that service can obtain a ticket-granting ticket (TGT) from the Key Distribution Center (KDC) on behalf of the user. With unconstrained delegation enabled, this service can then use the TGT to request service tickets for any other service in the domain, effectively impersonating the user.

Unconstrained delegation is generally discouraged unless absolutely necessary, and constrained delegation or resource-based delegation are preferred for more controlled and secure access delegation scenarios.

Here is how it works:

![Kerberos Unconstrained Delegation Flow](/assets/img/posts/kerberos/Unconstrained-Delegation.jpg)
_Unconstrained Delegation Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/unconstrained-delegation-too-trusting-for-its-own-good)_

> **Note**
> There are two missing steps in the diagram! The HTTP ST request and the actual ST presentation for accessing the HTTP service. Those steps would be between step 1 and 2, and inside step 3. Those steps are important because when the User asks for a ST for a service that is ok-as-delegate, the TGS service waits for the forwardable TGT request. 

1. The User requests a TGT ticket as seen in the [Understanding Kerberos](https://n10h0ggr.github.io/posts/You-do-(not)-Understand-Kerberos/) post.
2. The User requests the TGS for a Forwardable TGT.
3. Sends the ST and the forwardable TGT within the Authenticator.
4. Asks for webpage content.
5. The web page service account asks for a ST with User identity. It presents the TGT to demonstrate that User has been already authenticated to the service. 
6. The web service sends the User-ST to the DB to be authenticated. 
7. The DB sends the data.
8. The web is served to the user.

If we sniff the communication we would see something like this. Note that this packets are from a web server asking a SMB share and not a MSSQL. 

![Wireskark Unconstrained Delegation Flow](/assets/img/posts/kerberos/Wireshark-Unconstrained-Delegation.png)
_Unconstrained Delegation Packets_
_Source: [Attl4s](https://attl4s.github.io/assets/pdf/You_do_(not)_Understand_Kerberos_Delegation.pdf)_
### Constrained Delegation

Before explain Constrained Delegation we need to explain what S4U2 extensions are. There are 2 extensions used in Kerberos Delegation:

- **S4U2Self**: Allows a service to obtain a service ticket for itself on behalf of a client as evidence that the client has connected. Any service can use this. The resulting ST varies depending on the permissions of the service account it is associated with.
- **S4U2Proxy**: Allows a service to obtain a service ticket for a client for a different service. Requires a service ticket as evidence that the client has connected.

Knowing that, Constrained Delegation can  be configured in two ways:

1. **Kerberos only**: The service can delegate when the client authenticates via Kerberos. Uses S4U2Proxy methodology.
2. **Protocol transition**: Regardless of how the client connects, the service will be able to delegate credentials. Use both, S4U2Self and S4U2Proxy methodologies combined.

Enabling either of these configurations requires **Domain** or **Enterprise Admin** permissions as it need to activate the `SeEnableDelegation` attribute.

> **Important**
> It is essential to understand that in unconstrained delegation, it's the client that delegates the TGT to the service, but in unconstrained delegation with S4U2Proxy, the client delegates its ST to the service. 

#### Using Kerberos Only


![Kerberos authentication](/assets/img/posts/kerberos/Constrained-Delegation.jpg)
_Constrained Delegation Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/constrained-delegation-resource-based-delegation-outsmart-attacks)_

> **Note**
> When using this type of delegation in IIS the Kerberos Delegation with DFS Share the delegation settings have to be specified twice, one for the Share account and another for the IIS machine account. 

The full flow goes as follows:

3. The web service account (User A) requests a ST for the DB service for the user P account. Sends User A TGT and User P ST (the one used for accessing web service) as a prove for the TGS that the user P has connected to the service. 
4. The TGS checks if the ST is marked as Forwardeable and if web service account (User A) can delegate to db service account (User B); this is checked in the `mdDS-AllowedToDelegateTo` attribute of User A, as it shall have User B account as value. 
5. The web service sends the User P ST to the DB to be authenticated. 
6. The DB sends the data.

Sniff the communication would show us something like the following. Note that this packets are from a web server asking a SMB share and not a MSSQL. 

![[Pasted image 20240511184004.png]]

As we have seen, Kerberos only requires the user ST (that must be "forwardable") to allow a service to craft ST for that user. As a difference, here is the service who requests the ticket and not the user.

> **Note**
> **S4U2Self** cannot be used in this configuration, as the ST crafted from the TGS will be marked as non-forwardable and making the KDC fallback into RBCD. This will be discussed in next section. 

### Using Protocol Transition

This is performed when the client does not authenticate over Kerberos. Therefore, this is a way to use the service without providing evidence that the client has connected. Protocol Transition sets the `TRUSTED_TO_AUTH_FOR_DELEGATION UAC` setting.

This protocol uses both S4U2 extensions:

- **S4U2Self**: The service obtains a service ticket for itself on behalf of the client. The service sends its own TGT and the client's principal. The TGS checks if the service invoking the S4U2Self is trustworthy and has the `trusted_to_auth_for_delegation` attribute, then sends the ticket with the 'forwardable' feature; without this feature, the ticket is not valid. The service could perform S4U2Self without having said attribute, but the TGS would send a ticket without the 'forwardable' feature. If all conditions are met, it responds with an ST on behalf of the client for the service itself, thus obtaining a valid ST as proof to invoke S4U2Proxy.

- **S4U2Proxy**: The service requests an ST on behalf of the client for a second service and sends its own service ST as evidence that the client has authenticated. The TGS checks if the service for which the ticket is being requested is within the `mdDSmdDS-AllowedToDelegateTo` attribute. If everything is in order, it returns the ST. Now the service can use that ticket to connect to the service on behalf of the client.

When invoking S4U2Proxy with a 'non-forwardable' ST, an error occurs, and it falls back to RBCD. Therefore, RBCD does not require the ticket to be forwardable.

In protocol transition, the service has independence: with just the principal, it can request an ST for any user for any service, as the service to which the ST is directed is in plaintext for the service.

### Resource-Based Constrained Delegation

The RBCD flow is very similar as in Kerberos Only:

![Kerberos authentication](/assets/img/posts/kerberos/Resource-Based-Constrain-Delegation.jpg)
_RBCD Flow_
_Source: [crowe.com](https://www.crowe.com/cybersecurity-watch/constrained-delegation-resource-based-delegation-outsmart-attacks)_

3. The web service account (User A) requests a ST for the DB service for the user P account. Sends User A TGT and User P name.
4. The TGS checks if the ST is marked as Forwardeable and if web service account (User A) can delegate to db service account (User B); this is checked in the `mdDS-AllowedToDelegateTo` attribute of User A, as it shall have User B account as value. 
5. The web service sends the User P ST to the DB to be authenticated. 
6. The DB sends the data.

To configure this type of delegation, Domain or Enterprise Admin permissions are not required. Only write permissions on `ms-DS-AllowedToActOnBehalfOfOtherIdentiry` of a service account are needed.

Trust is configured in the service receiving the credential delegation. That is, it is in that second service where trust must be configured for the first service. "I, as a service, trust in this other service".

This applies to any authentication except Kerberos.
RBCD comes into play when the service does not have Constrained Delegation configured: When the service requests the TGS for an ST for its own service on behalf of the client, it sees that the service is not trusted (the `trusted_to_auth_for_delegation` is not activated, and thus unconstrained delegation is not active). The TGS sends a non-forwardable ST. The service then begins the S4U2Proxy flow with this non-forwardable ST. It sends the request to the TGS for this second service on behalf of the client and sends the non-forwardable ST as proof that the client has connected. The TGS, upon seeing this ST, checks if the service that made the request is trusted for the service the ST is being requested for. If it is trustworthy, everything is okay (they will know), and it sends a valid ST for this second service on behalf of the client.

To abuse RBCD, only write permissions for a service account are needed.
To invoke S4U2, you will always need an SPN. Any computer account has a default SPN.

In RBCD, you do not need to change the service name in the ST as in Constrained Delegation; you can simply obtain an ST for any service that trusts you. Most interestingly, it does not require DomainAdmin or Enterprise Admin permissions.

## How to Protect Yourself

1. There is the Protected Users group. If the user is a member of PROTECTED_USERS, the KDC will never issue a ticket with the PROXIABLE or FORWARDABLE flags activated.
   
2. Mark the account as sensitive and cannot be delegated. This bit indicates that its TGTs and STs cannot be marked as forwardable even if requested.
