---
title: Process Enumeration
date: 2025-08-20
categories:
  - Malware Development
  - Anti-Analysis Techniques
tags:
toc: "true"
---
Explanation on how to implement process enumeration in Windows and Linux, showing examples with APIs, access to the PEB, and use of the /proc system
### What does this technique consist of?

Process enumeration is one of the most commonly used techniques by malware to detect whether it is being analyzed in a controlled environment. Through this technique, malware can obtain a list of active processes in the system. With this list, it can compare the process names against a “blacklist” of security or analysis tools. If a match is found, it may choose to stop execution, change its behavior to something harmless, or even deploy a fake payload to confuse the analyst.

>**Note**  
>Process enumeration is conditioned by the privileges of the process that executes it. A user without elevated permissions may not have access to sensitive information from other processes (e.g., arguments, memory, or loaded modules). On the other hand, with administrative/root privileges, visibility is practically total.

Next, we will see several ways of implementing this technique for both Windows and Linux systems.

### Windows Process Enumeration

In Windows, the most common way to perform process enumeration is through the Toolhelp32 API, which allows capturing a snapshot of all processes and iterating through them one by one. Other variants include using EnumProcesses or even direct access to the Process Environment Block (PEB), a stealthier but more complex technique.

#### Process enumeration with Toolhelp32

The Toolhelp32 API is probably the most widely used method for enumerating processes in Windows. It allows creating a “snapshot” of all active processes and iterating through them one by one using the Process32First and Process32Next functions.

This method is simple to implement and well documented, making it a common choice for both developers and malware authors.

Here’s an example in C++ of how we could implement this enumeration:

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int main() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot" << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::wcout << L"Process: " << pe32.szExeFile 
                       << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;

            // Detection example
            if (_wcsicmp(pe32.szExeFile, L"procmon.exe") == 0) {
                std::cout << "[!] Analysis process detected" << std::endl;
                break;
            }

        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}
```

In this example, we use the `CreateToolhelp32Snapshot` function to create a snapshot of the active processes. This returns a doubly linked list where each node contains the data of an active process. To access the elements of this list, Windows provides `Process32First` and `Process32Next`. In the example, we use a do-while loop to iterate through all active processes and obtain data such as their name or PID.

#### Process enumeration with EnumProcesses

Another common way of obtaining the process list in Windows is through the EnumProcesses API, which is part of the **PSAPI.dll** (Process Status API). Unlike Toolhelp32, this method does not directly return process information but instead an array with all active Process IDs (PIDs). Once the PIDs are obtained, each process must be opened individually, and its modules must be queried to get the executable name.

This approach is somewhat more complex than Toolhelp32 because it requires more steps, but it is very flexible: in addition to the process name, it allows access to detailed information about loaded modules.

Here’s an example in C++:

```cpp
#include <windows.h>
#include <psapi.h>
#include <iostream>

int main() {
    DWORD processes[1024], bytesReturned;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        std::cerr << "Error in EnumProcesses" << std::endl;
        return 1;
    }

    DWORD count = bytesReturned / sizeof(DWORD);

    for (unsigned int i = 0; i < count; i++) {
        if (processes[i] == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            HMODULE hMod;
            DWORD needed;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &needed)) {
                char processName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName))) {
                    std::cout << "Process: " << processName 
                              << " (PID: " << processes[i] << ")" << std::endl;

                    if (_stricmp(processName, "idaq.exe") == 0) {
                        std::cout << "[!] Debugger detected" << std::endl;
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}
```

Here, we first use `EnumProcesses` to get all running process IDs. Then, we open each of them with `OpenProcess` to gain access to internal information. Using `EnumProcessModules`, we retrieve the first loaded module (usually the main executable), and with `GetModuleBaseName` we extract its name. This way, we can iterate through all active processes and compare them against a list of interest, just like malware looking for analysis tools on the system would do.

#### Process enumeration through the PEB

The most stealthy and advanced method for enumerating processes consists of directly accessing the **Process Environment Block (PEB)**. The PEB is an internal Windows structure containing key information about the running process, including pointers to the list of loaded modules and other execution parameters.

Unlike higher-level APIs, which can be easily monitored by an EDR, direct access to the PEB allows malware to obtain information without leaving an obvious trace. This makes it an attractive technique for malware families that want to evade detection during dynamic analysis.

Here’s an example in C that accesses the PEB in a 32-bit process:

```c
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

int main() {
    // En x86: FS:[0x30] contiene un puntero al PEB
    PPEB pPEB = (PPEB)__readfsdword(0x30);

    if (pPEB && pPEB->Ldr) {
        LIST_ENTRY* pListHead = &pPEB->Ldr->InLoadOrderModuleList;
        LIST_ENTRY* pListCurrent = pListHead->Flink;

        while (pListCurrent != pListHead) {
            PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)pListCurrent;

            if (pEntry->BaseDllName.Buffer) {
                wprintf(L"Modulo: %wZ\n", &pEntry->BaseDllName);

                // Comparación con un módulo concreto
                if (_wcsicmp(pEntry->BaseDllName.Buffer, L"procmon.exe") == 0) {
                    printf("[!] Proceso de análisis detectado\n");
                    break;
                }
            }

            pListCurrent = pListCurrent->Flink;
        }
    }

    return 0;
}
```

In this case, we access the PEB from the FS segment and, through the `PEB_LDR_DATA` structure, iterate over the doubly linked list of loaded modules (`InLoadOrderModuleList`). Each entry contains module information, including its name. The example prints the modules found and compares them with `procmon.exe`.

In this way, malware achieves the same as with Toolhelp32 or EnumProcesses, but without relying on Windows API calls. This is beneficial since it avoids API calls that could be monitored or show suspicious functions in the import table.

### Process Enumeration in Linux

In Linux, process enumeration mainly relies on the `/proc` pseudo-filesystem, which exposes detailed information about every active process. This mechanism is used both by legitimate tools such as **ps** or **top**, as well as by malware looking to detect analysis environments.

Another alternative is using libraries such as **libproc2** (used internally by `ps`), which offer a simpler interface for accessing the same information.

#### Process enumeration with `/proc`

The most common and direct method is to iterate over the `/proc` directory. Each subdirectory whose name is a number corresponds to a running PID, and inside we can find:

- `/proc/<pid>/exe` → symbolic link to the executable
- `/proc/<pid>/cmdline` → command line used
- `/proc/<pid>/status` → general information (UID, state, memory)

```c
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static int is_number(const char *s) {
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

int main(void) {
    DIR *d = opendir("/proc");
    if (!d) { perror("opendir"); return 1; }

    struct dirent *de;
    while ((de = readdir(d))) {
        if (!is_number(de->d_name)) continue;

        char path[PATH_MAX], exe[PATH_MAX];
        ssize_t n;

        snprintf(path, sizeof(path), "/proc/%s/exe", de->d_name);
        n = readlink(path, exe, sizeof(exe)-1);
        if (n >= 0) exe[n] = '\0';
        else strcpy(exe, "?");

        printf("Proceso: %s (PID: %s)\n", exe, de->d_name);

        // Ejemplo
        if (strstr(exe, "strace") != NULL) {
            printf("[!] Herramienta de análisis detectada\n");
            break;
        }
    }
    closedir(d);
    return 0;
}
```

Here, we open `/proc`, iterate through numeric entries (PIDs), and resolve the symbolic link `exe`, which points to the running binary. This allows us to iterate through all active processes and compare their executables against a blacklist.

#### Process enumeration with libproc2

Another widely used method is relying on **libproc2**, part of the **procps-ng** package. Instead of manually reading `/proc`, this library abstracts details and returns structures with already parsed fields: PID, name, UID, memory usage, state, etc.

```c
#include <proc/readproc.h>
#include <stdio.h>
#include <string.h>

int main() {
    PROCTAB* pt = openproc(PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLMEM);
    proc_t proc_info;

    while (readproc(pt, &proc_info) != NULL) {
        printf("Proceso: %s (PID: %d, UID: %d)\n",
               proc_info.cmd, proc_info.tid, proc_info.euid);

        // Ejemplo
        if (strcmp(proc_info.cmd, "gdb") == 0) {
            printf("[!] Debugger detectado\n");
            break;
        }
    }
    closeproc(pt);
    return 0;
}
```

Here we use `openproc` to initialize the process table and `readproc` to iterate over them. This method is more convenient than manually parsing `/proc`, since it provides already organized information. However, it introduces an additional dependency, which may reveal the malware if the binary needs to be linked against this library.

#### Bonus: Enumerating libraries with `/proc/<pid>/maps`

A more advanced approach consists of analyzing the modules loaded by a process. In Linux, there is no equivalent structure to Windows’ PEB, but this information can be found in `/proc/<pid>/maps`. This file lists all mapped memory regions, including dynamic libraries (`.so`) loaded by the binary.

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <pid>\n", argv[0]);
        return 1;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", argv[1]);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen"); return 1; }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *lib = strchr(line, '/');
        if (lib) {
            printf("Módulo: %s", lib);

            // Ejemplo
            if (strstr(lib, "libaudit.so") != NULL) {
                printf("[!] Librería de auditoría detectada\n");
                break;
            }
        }
    }
    fclose(f);
    return 0;
}
```

In this example, we iterate through mapped memory regions and print loaded libraries. Malware could use this technique to identify if a process has loaded libraries associated with an EDR or AV and modify its behavior accordingly.
