---
title: Indirect Syscalls
date: 2024-07-14
categories:
  - malware
tags:
  - english
toc: "true"
---
## Indirect Syscalls
To avoid detection by EDR and eliminate this indicator of compromise (IOC) from an attacker's (or Red Team's) perspective, direct syscalls can be substituted with indirect syscalls. Indirect syscalls are essentially an evolution of direct syscalls, designed to perform syscall and return statements within the memory of ntdll.dll, rather than the memory of the executing file. This method aligns more closely with standard operating behavior in Windows environments, making it a more compliant technique and therefore most difficult to detect.
