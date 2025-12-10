#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: object_identifier, is_object_dn, search_ou, dc_address, use_ldaps
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
    
    // Get default naming context (needed for searches if DN not provided)
    char* defaultNC = NULL;
    char* objectDN = NULL;
    
    if (!isObjectDN) {
        
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Resolve object DN
    if (isObjectDN) {
        // Object identifier is already a DN
        size_t len = MSVCRT$strlen(objectIdentifier) + 1;
        objectDN = (char*)MSVCRT$malloc(len);
        if (objectDN) {
            MSVCRT$strcpy(objectDN, objectIdentifier);
        }
    } else {
        // Search for object by sAMAccountName
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        objectDN = FindObjectDN(ld, objectIdentifier, searchBase);
        
        if (!objectDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve object DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Object '%s' not found", objectIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Delete the object
    ULONG result = WLDAP32$ldap_delete_s(ld, objectDN);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully deleted object");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s", objectDN);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete object");
        PrintLdapError("Delete object", result);
        
        // Provide helpful hints
        if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Object does not exist");
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions to delete object");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax");
        }
    }
    
    // Cleanup
    if (defaultNC) MSVCRT$free(defaultNC);
    if (objectDN) MSVCRT$free(objectDN);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}