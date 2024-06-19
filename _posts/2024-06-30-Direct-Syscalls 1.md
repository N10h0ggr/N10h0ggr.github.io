---
title: Direct Syscalls
date: 2024-06-30
categories:
  - malware
tags:
  - english
toc: "true"
---
In recent years, many EDR vendors have implemented user mode hooking. This allows EDR systems to analyze and potentially redirect code executed in the context of Windows APIs. If the code does not appear malicious, the system call is executed correctly; otherwise, execution is prevented. User mode hooking makes it harder to execute malware, so attackers use techniques like API unhooking, direct system calls, or indirect system calls to bypass EDRs.

This article will dive into how to use system calls to evade EDRs and AVs. First, we'll introduce the different techniques used by malware developers over the years and how they have improved. Once we cover these basics, a practical implementation in Rust will be presented, showing the code and how to use it. 

Let's begin with the basics

## What Are Syscalls?
Syscalls are the primary means by which user-level applications interact with the kernel of an operating system. They enable operations such as file manipulation, process control, and network communication. For instance, when a program needs to open a file, it makes a syscall to request the OS to perform this action on its behalf.

## Syscalls In The Cybersecurity World

Syscalls play a pivotal role in both malware attacks and defense mechanisms. Anti-virus (AV) and endpoint detection and response (EDR) products implement user-mode API hooking to protect against malware, using trampolines and therefore placing syscalls inside Windows API functions. Those hooks have the function to dynamically inspect potentially malicious code in the context of Windows APIs.

> **Note**
> 
> Before the introduction of **Kernel Patch Protection (KPP)** aka Patch Guard, it was possible for antivirus products to implement their hooks in the Windows kernel, e.g. using **SSDT hooking**. With **Patch Guard**, this was **prevented** by Microsoft for reasons of operating system stability. Now, AVs and EDRs place their hooks inside ntdll.dll, the native layer, just before the kernel world.

For performance reasons, EDRs and AVs do not hook all the native functions. Hooking APIs costs resources, time, etc., slowing down the OS. FOr this reason, security solutions typically only hook select APIs that are often related to malware behavior such as NtAllocateVirtualMemory and NtWriteVirtualMemory. 

> **Note**
> 
> If you want to check your own EDR to see which APIs are hooked by inline hooking you can use a debugger such as WinDbg. Run a program such notepad.exe or calc.exe and once its running place attach the debugger to it. 

## Direct Syscalls
Direct system calls are a technique attackers use to execute code via system calls without referencing Windows APIs from kernel32.dll or native APIs from ntdll.dll. Each system call has a unique syscall ID that can differ between Windows versions. Attackers achieve this by directly invoking the syscall instruction with the desired syscall ID, bypassing the typical API function hooks that EDRs could place.

This method is popular among attackers and Red Teamers for tasks like executing shellcode or creating a memory dump from lsass.exe. However, its effectiveness is decreasing. Many EDR vendors now implement **kernel callbacks** to monitor the memory areas from which syscall and return statements are executed. If a return statement originates outside the ntdll.dll memory area, it is flagged as suspicious behavior, triggering an alert.

There are several tools and POCs available to implement and execute direct syscalls, such as Syswhispers2, Syswhispers3, Hells Gate or Halo's Gate. In our case, we will create an enhanced version of Halo's gate, but in using Rust. In following posts we will make some modifications to be able to use indirect syscalls too. 

But first, we need to understand how to know which syscall ID correspond to what function.

### Collecting the IDs
talk about different approaches and then show the halos gate code

## Code Time
show the full code and an example of the usage

We will try to keep the code as simple as possible, making it a library to use in our projects. The code can also be downloaded from my Github repository for educational and testing purposes. 



## Indirect Syscalls
To avoid detection by EDR and eliminate this indicator of compromise (IOC) from an attacker's (or Red Team's) perspective, direct syscalls can be substituted with indirect syscalls. Indirect syscalls are essentially an evolution of direct syscalls, designed to perform syscall and return statements within the memory of ntdll.dll, rather than the memory of the executing file. This method aligns more closely with standard operating behavior in Windows environments, making it a more compliant technique and therefore most difficult to detect.
