// ldap_common.c - Shared LDAP utilities for BOF operations
// This file should be #included in each BOF that uses these functions

#include <windows.h>
#include "ldap_common.h"

// Import required MSVCRT functions
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char* str1, const char* str2, size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char* dest, const char* src);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char *str, int c);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char* str, const char* substr);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);

// Import kernel32 functions
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);

#define CP_UTF8 65001
#define CP_ACP 0

// SSL certificate callback - accepts all certificates
BOOLEAN ServerCertCallback(PLDAP Connection, PCCERT_CONTEXT pServerCert) {
    return TRUE;
}

// Convert char* to wchar_t*
wchar_t* CharToWChar(const char* str) {
    if (!str) return NULL;
    
    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;
    
    wchar_t* wstr = (wchar_t*)MSVCRT$malloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}

// Convert wchar_t* to char*
char* WCharToChar(const wchar_t* wstr) {
    if (!wstr) return NULL;
    
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len == 0) return NULL;
    
    char* str = (char*)MSVCRT$malloc(len);
    if (!str) return NULL;
    
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
    return str;
}

// Simple helper that returns NULL if input doesn't start with a letter or number
char* ValidateInput(char* input) {
    if (input == NULL)
        return NULL;

    if ((input[0] >= 'A' && input[0] <= 'Z') ||
        (input[0] >= 'a' && input[0] <= 'z') ||
        (input[0] >= '0' && input[0] <= '9')){
        return input;
    }

    return NULL;
}

// Get Domain Controller hostname
char* GetDCHostName() {
    PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
    char* dcHostname = NULL;
    
    DWORD dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
    
    if (dwRet == 0 && pdcInfo) {  // ERROR_SUCCESS = 0
        // DomainControllerName starts with "\\" - skip those
        char* dcName = pdcInfo->DomainControllerName;
        if (dcName && dcName[0] == '\\' && dcName[1] == '\\') {
            dcName += 2;  // Skip the "\\"
        }
        
        // Allocate and copy the hostname
        if (dcName) {
            size_t len = MSVCRT$strlen(dcName) + 1;
            dcHostname = (char*)MSVCRT$malloc(len);
            if (dcHostname) {
                MSVCRT$strcpy(dcHostname, dcName);
            }
        }
        
        // Free the buffer allocated by DsGetDcNameA
        NETAPI32$NetApiBufferFree(pdcInfo);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to identify DC. Are we domain joined?");
    }
    
    return dcHostname;
}

// Build default naming context from DC hostname
// Converts "winterfell.north.sevenkingdoms.local" to "DC=north,DC=sevenkingdoms,DC=local"
char* BuildDefaultNamingContextFromDC(const char* dcHostname) {
    if (!dcHostname || MSVCRT$strlen(dcHostname) == 0) return NULL;
    
    // Find first dot to skip hostname portion
    const char* domainStart = MSVCRT$strchr(dcHostname, '.');
    if (!domainStart || *(domainStart + 1) == '\0') {
        // No domain component found
        return NULL;
    }
    
    domainStart++; // Skip the dot
    
    // Count dots to determine number of DC components needed
    int dotCount = 0;
    const char* p = domainStart;
    while (*p) {
        if (*p == '.') dotCount++;
        p++;
    }
    
    // Calculate required buffer size: "DC=" (3) + label + "," per component, minus last comma
    size_t domainLen = MSVCRT$strlen(domainStart);
    size_t bufferSize = domainLen + (dotCount + 1) * 3 + dotCount + 1; // +1 for null terminator
    
    char* defaultNC = (char*)MSVCRT$malloc(bufferSize);
    if (!defaultNC) return NULL;
    
    // Build the DN: DC=north,DC=sevenkingdoms,DC=local
    char* writePos = defaultNC;
    const char* readPos = domainStart;
    BOOL firstComponent = TRUE;
    
    while (*readPos) {
        // Add comma separator (except for first component)
        if (!firstComponent) {
            *writePos++ = ',';
        }
        firstComponent = FALSE;
        
        // Add "DC="
        *writePos++ = 'D';
        *writePos++ = 'C';
        *writePos++ = '=';
        
        // Copy label until dot or end
        while (*readPos && *readPos != '.') {
            *writePos++ = *readPos++;
        }
        
        // Skip the dot if present
        if (*readPos == '.') readPos++;
    }
    
    *writePos = '\0';
    return defaultNC;
}

// Initialize LDAP connection with proper authentication
LDAP* InitializeLDAPConnection(const char* dcAddress, BOOL useLdaps, char** outDcHostname) {
    LDAP* pLdapConnection = NULL;
    ULONG result;
    int portNumber = useLdaps ? LDAP_SSL_PORT : LDAP_PORT;
    char* discoveredDC = NULL;
    char* targetDC = NULL;

    // If no DC address provided, auto-discover it
    if (!dcAddress || MSVCRT$strlen(dcAddress) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No DC specified, auto-discovering...");
        discoveredDC = GetDCHostName();
        if (!discoveredDC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to discover DC");
            return NULL;
        }
        targetDC = discoveredDC;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Discovered DC: %s", targetDC);
    } else {
        targetDC = (char*)dcAddress;
    }

    // Store hostname for later use
    if (outDcHostname) {
        size_t len = MSVCRT$strlen(targetDC) + 1;
        *outDcHostname = (char*)MSVCRT$malloc(len);
        if (*outDcHostname) {
            MSVCRT$strcpy(*outDcHostname, targetDC);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to: %s:%d", targetDC, portNumber);
    
    // Use ldap_init with hostname (ANSI version)
    pLdapConnection = WLDAP32$ldap_init((PCHAR)targetDC, portNumber);
    if (!pLdapConnection) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection on port %d", portNumber);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    // Set LDAP version to 3 (required)
    ULONG version = LDAP_VERSION3;
    result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set LDAP version: %lu", result);
        WLDAP32$ldap_unbind_s(pLdapConnection);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    if (useLdaps) {
        // For LDAPS (port 636), enable SSL
        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enable SSL: %lu", result);
            WLDAP32$ldap_unbind_s(pLdapConnection);
            if (discoveredDC) MSVCRT$free(discoveredDC);
            return NULL;
        }

        // Set certificate callback
        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set certificate callback: %lu", result);
        }
    } else {
        // For regular LDAP (port 389), enable signing and sealing
        // These need to be set BEFORE binding with NEGOTIATE auth
        void* value = LDAP_OPT_ON;
        
        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SIGN, &value);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Warning: Failed to enable LDAP signing: %lu", result);
        }

        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_ENCRYPT, &value);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Warning: Failed to enable LDAP encryption: %lu", result);
        }
    }

    // Bind using current credentials (NEGOTIATE)
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Binding to LDAP...");
    result = WLDAP32$ldap_bind_s(pLdapConnection, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to bind to LDAP");
        PrintLdapError("Bind", result);
        WLDAP32$ldap_unbind_s(pLdapConnection);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully bound to LDAP");
    
    // Free discovered DC hostname if we allocated it
    if (discoveredDC) {
        MSVCRT$free(discoveredDC);
    }
    
    return pLdapConnection;
}

// Get default naming context from rootDSE
char* GetDefaultNamingContext(LDAP* ld, const char* dcHostname) {
    if (!ld) return NULL;
    
    // Try to build from DC hostname first (faster, no network query)
    if (dcHostname && MSVCRT$strlen(dcHostname) > 0) {
        char* defaultNC = BuildDefaultNamingContextFromDC(dcHostname);
        if (defaultNC) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Default naming context: %s", defaultNC);
            return defaultNC;
        }
        // If building failed, fall through to query method
    }
    
    // Fallback: Query rootDSE (original implementation)
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char* attrs[] = { "defaultNamingContext", NULL };
    char** values = NULL;
    char* defaultNC = NULL;

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        "",                         // Empty base DN for rootDSE
        LDAP_SCOPE_BASE,           // Base scope
        "(objectClass=*)",         // Match everything
        attrs,                     // Attributes
        0,                         // Return attributes and values
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query rootDSE");
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    values = WLDAP32$ldap_get_values(ld, entry, "defaultNamingContext");
    if (values && values[0]) {
        size_t len = MSVCRT$strlen(values[0]) + 1;
        defaultNC = (char*)MSVCRT$malloc(len);
        if (defaultNC) {
            MSVCRT$strcpy(defaultNC, values[0]);
        }
        WLDAP32$ldap_value_free(values);
    }

    WLDAP32$ldap_msgfree(searchResult);
    return defaultNC;
}

// Find object DN by sAMAccountName
char* FindObjectDN(LDAP* ld, const char* samAccountName, const char* searchBase) {
    if (!ld || !samAccountName) return NULL;

    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char filter[512];
    char* attrs[] = { "distinguishedName", NULL };
    char** values = NULL;
    char* objectDN = NULL;

    // Build search filter
    MSVCRT$_snprintf(filter, sizeof(filter), "(sAMAccountName=%s)", samAccountName);

    // Search for the object
    ULONG result = WLDAP32$ldap_search_s(
        ld,
        (char*)searchBase,
        LDAP_SCOPE_SUBTREE,
        filter,
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for object '%s'", samAccountName);
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object '%s' not found", samAccountName);
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    values = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");
    if (values && values[0]) {
        size_t len = MSVCRT$strlen(values[0]) + 1;
        objectDN = (char*)MSVCRT$malloc(len);
        if (objectDN) {
            MSVCRT$strcpy(objectDN, values[0]);
        }
        WLDAP32$ldap_value_free(values);
    }

    WLDAP32$ldap_msgfree(searchResult);
    return objectDN;
}

// Print LDAP error with context
void PrintLdapError(const char* context, ULONG ldapError) {
    char* errorMsg = WLDAP32$ldap_err2stringA(ldapError);
    if (errorMsg) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s - LDAP Error (0x%x): %s", context, ldapError, errorMsg);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s - LDAP Error: 0x%x", context, ldapError);
    }
}

// Encode password for unicodePwd attribute (UTF-16LE with quotes)
BERVAL* EncodePassword(const char* password) {
    if (!password || MSVCRT$strlen(password) == 0) return NULL;

    // Create quoted password string
    size_t passLen = MSVCRT$strlen(password);
    char* quotedPass = (char*)MSVCRT$malloc(passLen + 3);
    if (!quotedPass) return NULL;

    quotedPass[0] = '"';
    MSVCRT$memcpy(quotedPass + 1, password, passLen);
    quotedPass[passLen + 1] = '"';
    quotedPass[passLen + 2] = '\0';

    // Convert to UTF-16LE
    int wideLen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, quotedPass, -1, NULL, 0);
    if (wideLen == 0) {
        MSVCRT$free(quotedPass);
        return NULL;
    }

    wchar_t* widePass = (wchar_t*)MSVCRT$malloc(wideLen * sizeof(wchar_t));
    if (!widePass) {
        MSVCRT$free(quotedPass);
        return NULL;
    }

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, quotedPass, -1, widePass, wideLen);
    MSVCRT$free(quotedPass);

    // Create BERVAL
    BERVAL* berval = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (!berval) {
        MSVCRT$free(widePass);
        return NULL;
    }

    berval->bv_len = (wideLen - 1) * sizeof(wchar_t); // Exclude null terminator
    berval->bv_val = (char*)widePass;

    return berval;
}

// Cleanup LDAP connection
void CleanupLDAP(LDAP* ld) {
    if (ld) {
        WLDAP32$ldap_unbind_s(ld);
    }
}