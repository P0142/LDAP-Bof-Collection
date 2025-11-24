#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: target_identifier, is_dn, attribute, search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* attribute = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }

    if (!attribute || MSVCRT$strlen(attribute) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Attribute name is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting attribute query");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attribute: %s", attribute);

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
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target DN: %s", targetDN);
    }

    // Query the specific attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { attribute, NULL };

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
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query attribute");
        PrintLdapError("Query attribute", result);
        MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** values = WLDAP32$ldap_get_values(ld, entry, attribute);
        if (values) {
            int valueCount = WLDAP32$ldap_count_values(values);
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Attribute '%s' (%d value(s)):", attribute, valueCount);
            BeaconPrintf(CALLBACK_OUTPUT, "==========================================");
            for (int i = 0; values[i] != NULL; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s", values[i]);
            }
            WLDAP32$ldap_value_free(values);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Attribute '%s' not found or has no value", attribute);
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Operation complete");
}
