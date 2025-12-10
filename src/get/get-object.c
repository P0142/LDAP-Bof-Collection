#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: object_identifier, is_dn, search_ou, dc_address, use_ldaps
    char* objectIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isObjectDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!objectIdentifier || MSVCRT$strlen(objectIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object identifier is required");
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
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Resolve object DN
    char* objectDN = NULL;
    if (isObjectDN) {
        size_t len = MSVCRT$strlen(objectIdentifier) + 1;
        objectDN = (char*)MSVCRT$malloc(len);
        if (objectDN) {
            MSVCRT$strcpy(objectDN, objectIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        objectDN = FindObjectDN(ld, objectIdentifier, searchBase);
        if (!objectDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Object '%s' not found", objectIdentifier);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Query all attributes
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "*", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        objectDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query object");
        PrintLdapError("Query object", result);
        MSVCRT$free(objectDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Object attributes:\n======================");

        // Iterate through all attributes
        BerElement* ber = NULL;
        char* attribute = WLDAP32$ldap_first_attribute(ld, entry, &ber);
        while (attribute != NULL) {
            // Check if this is a known binary attribute (case-insensitive)
            BOOL isBinary = (MSVCRT$_stricmp(attribute, "objectGUID") == 0 || 
                            MSVCRT$_stricmp(attribute, "objectSid") == 0 ||
                            MSVCRT$_stricmp(attribute, "objectSID") == 0);
            
            if (isBinary) {
                // Handle binary attributes
                struct berval** bvalues = WLDAP32$ldap_get_values_len(ld, entry, attribute);
                if (bvalues && bvalues[0]) {
                    char formatted[256];
                    if (MSVCRT$_stricmp(attribute, "objectGUID") == 0) {
                        FormatGUID((BYTE*)bvalues[0]->bv_val, formatted);
                        BeaconPrintf(CALLBACK_OUTPUT, "%-30s : %s", attribute, formatted);
                    } else if (MSVCRT$_stricmp(attribute, "objectSid") == 0 || 
                               MSVCRT$_stricmp(attribute, "objectSID") == 0) {
                        FormatSID((BYTE*)bvalues[0]->bv_val, bvalues[0]->bv_len, formatted);
                        BeaconPrintf(CALLBACK_OUTPUT, "%-30s : %s", attribute, formatted);
                    }
                }
                if (bvalues) WLDAP32$ldap_value_free_len(bvalues);
            } else {
                // Handle string attributes
                char** values = WLDAP32$ldap_get_values(ld, entry, attribute);
                if (values) {
                    for (int i = 0; values[i] != NULL; i++) {
                        BeaconPrintf(CALLBACK_OUTPUT, "%-30s : %s", attribute, values[i]);
                    }
                    WLDAP32$ldap_value_free(values);
                }
            }
            
            WLDAP32$ldap_memfree(attribute);
            attribute = WLDAP32$ldap_next_attribute(ld, entry, ber);
        }
        if (ber) WLDAP32$ber_free(ber, 0);
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(objectDN);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
