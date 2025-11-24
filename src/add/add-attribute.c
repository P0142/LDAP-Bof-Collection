#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: target_identifier, is_dn, attribute, value, search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* attribute = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* value = ValidateInput(BeaconDataExtract(&parser, NULL));
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

    if (!value || MSVCRT$strlen(value) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Value is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting add attribute operation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attribute: %s", attribute);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Value: %s", value);

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

    // Add attribute value
    char* attr_values[] = { value, NULL };
    LDAPModA attr_mod;
    attr_mod.mod_op = LDAP_MOD_ADD;
    attr_mod.mod_type = attribute;
    attr_mod.mod_vals.modv_strvals = attr_values;

    LDAPModA* mods[] = { &attr_mod, NULL };

    ULONG result = WLDAP32$ldap_modify_s(ld, targetDN, mods);

    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully added value to '%s'", attribute);
    } else if (result == LDAP_ATTRIBUTE_OR_VALUE_EXISTS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Value already exists for attribute '%s'", attribute);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add attribute value");
        PrintLdapError("Add attribute", result);
    }

    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}
