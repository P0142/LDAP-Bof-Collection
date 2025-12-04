#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char* buffer, const char* format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char* str1, const char* str2);

// Convert binary GUID to string format
void FormatGUID(BYTE* guidBytes, char* output) {
    MSVCRT$sprintf(output, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guidBytes[3], guidBytes[2], guidBytes[1], guidBytes[0],
        guidBytes[5], guidBytes[4],
        guidBytes[7], guidBytes[6],
        guidBytes[8], guidBytes[9],
        guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15]);
}

// Convert binary SID to string format (simplified - handles common SIDs)
void FormatSID(BYTE* sidBytes, int length, char* output) {
    if (length < 8) {
        MSVCRT$sprintf(output, "(invalid SID)");
        return;
    }
    
    BYTE revision = sidBytes[0];
    BYTE subAuthCount = sidBytes[1];
    
    // Authority (6 bytes, big-endian)
    unsigned long long authority = 0;
    for (int i = 0; i < 6; i++) {
        authority = (authority << 8) | sidBytes[2 + i];
    }
    
    // Start building the SID string
    int pos = MSVCRT$sprintf(output, "S-%d-%llu", revision, authority);
    
    // SubAuthorities (32-bit values, little-endian)
    for (int i = 0; i < subAuthCount && (8 + i * 4 + 3) < length; i++) {
        unsigned long subAuth = 
            (unsigned long)sidBytes[8 + i * 4] |
            ((unsigned long)sidBytes[8 + i * 4 + 1] << 8) |
            ((unsigned long)sidBytes[8 + i * 4 + 2] << 16) |
            ((unsigned long)sidBytes[8 + i * 4 + 3] << 24);
        pos += MSVCRT$sprintf(output + pos, "-%lu", subAuth);
    }
}

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
        // Check if this is a known binary attribute (case-insensitive)
        BOOL isBinary = (MSVCRT$_stricmp(attribute, "objectGUID") == 0 || 
                        MSVCRT$_stricmp(attribute, "objectSid") == 0 ||
                        MSVCRT$_stricmp(attribute, "objectSID") == 0);
        
        if (isBinary) {
            // Handle binary attributes
            struct berval** bvalues = WLDAP32$ldap_get_values_len(ld, entry, attribute);
            if (bvalues && bvalues[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "==========================================");
                for (int i = 0; bvalues[i] != NULL; i++) {
                    char formatted[256];
                    if (MSVCRT$_stricmp(attribute, "objectGUID") == 0) {
                        FormatGUID((BYTE*)bvalues[i]->bv_val, formatted);
                        BeaconPrintf(CALLBACK_OUTPUT, "%s", formatted);
                    } else if (MSVCRT$_stricmp(attribute, "objectSid") == 0 || 
                               MSVCRT$_stricmp(attribute, "objectSID") == 0) {
                        FormatSID((BYTE*)bvalues[i]->bv_val, bvalues[i]->bv_len, formatted);
                        BeaconPrintf(CALLBACK_OUTPUT, "%s", formatted);
                    }
                }
                WLDAP32$ldap_value_free_len(bvalues);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "==========================================");
                BeaconPrintf(CALLBACK_OUTPUT, "(No value found)");
            }
        } else {
            // Handle string attributes
            char** values = WLDAP32$ldap_get_values(ld, entry, attribute);
            if (values) {
                BeaconPrintf(CALLBACK_OUTPUT, "==========================================");
                for (int i = 0; values[i] != NULL; i++) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", values[i]);
                }
                WLDAP32$ldap_value_free(values);
            }
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
