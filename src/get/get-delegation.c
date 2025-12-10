#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char* str, char** endptr, int base);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: target_identifier, is_dn, search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }

    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }

    // Get default naming context
    char* defaultNC = NULL;
    if (!isTargetDN) {
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Resolve target DN
    char* targetDN = NULL;
    if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, targetIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", targetIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Query delegation attributes
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "msDS-AllowedToDelegateTo", "userAccountControl", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        targetDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query delegation");
        PrintLdapError("Query delegation", result);
        MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Delegation Configuration:");
        BeaconPrintf(CALLBACK_OUTPUT, "==============================");

        // Check UAC for delegation flags
        char** uacValues = WLDAP32$ldap_get_values(ld, entry, "userAccountControl");
        if (uacValues && uacValues[0]) {
            DWORD uac = (DWORD)MSVCRT$strtol(uacValues[0], NULL, 10);
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] UAC Delegation Flags:");

            if (uac & UF_TRUSTED_FOR_DELEGATION) {
                BeaconPrintf(CALLBACK_OUTPUT, "    [!] TRUSTED_FOR_DELEGATION (Unconstrained delegation enabled)");
            }
            if (uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION) {
                BeaconPrintf(CALLBACK_OUTPUT, "    [!] TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol transition enabled)");
            }
            if (uac & UF_NOT_DELEGATED) {
                BeaconPrintf(CALLBACK_OUTPUT, "    [*] NOT_DELEGATED (Account cannot be delegated)");
            }
            if (!(uac & (UF_TRUSTED_FOR_DELEGATION | UF_TRUSTED_TO_AUTH_FOR_DELEGATION | UF_NOT_DELEGATED))) {
                BeaconPrintf(CALLBACK_OUTPUT, "    [*] No delegation flags set");
            }
            WLDAP32$ldap_value_free(uacValues);
        }

        // Get constrained delegation SPNs
        char** delegateValues = WLDAP32$ldap_get_values(ld, entry, "msDS-AllowedToDelegateTo");
        if (delegateValues) {
            int spnCount = WLDAP32$ldap_count_values(delegateValues);
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Constrained Delegation SPNs (%d):", spnCount);
            for (int i = 0; delegateValues[i] != NULL; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "    %s", delegateValues[i]);
            }
            WLDAP32$ldap_value_free(delegateValues);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] No constrained delegation SPNs configured");
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
