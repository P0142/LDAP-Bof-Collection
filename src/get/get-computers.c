#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: search_ou, dc_address, use_ldaps, attributes
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    char* attributesStr = ValidateInput(BeaconDataExtract(&parser, NULL));

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

    char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;

    // Build attribute list
    char* attrs[64];
    char* defaultAttrs[] = { "distinguishedName", "operatingSystem" };
    int attrCount = BuildAttributeList(attributesStr, defaultAttrs, 2, attrs, 64);

    // Check if ntSecurityDescriptor is requested (case-insensitive)
    BOOL needSDFlags = FALSE;
    for (int i = 0; i < attrCount; i++) {
        if (MSVCRT$_stricmp(attrs[i], "ntSecurityDescriptor") == 0) {
            needSDFlags = TRUE;
            break;
        }
    }

    // Search for computer objects
    LDAPMessage* searchResult = NULL;
    ULONG result;

    if (needSDFlags) {
        // Create SD_FLAGS control for ntSecurityDescriptor
        DWORD sdFlags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        
        char sdFlagsBuffer[10];
        struct berval sdFlagsValue;
        LDAPControlA* sdFlagsControl = BuildSDFlagsControl(sdFlags, sdFlagsBuffer, &sdFlagsValue);
        
        LDAPControlA* serverControls[] = { sdFlagsControl, NULL };

        result = WLDAP32$ldap_search_ext_s(
            ld,
            searchBase,
            LDAP_SCOPE_SUBTREE,
            "(objectClass=computer)",
            attrs,
            0,
            serverControls,
            NULL,           // ClientControls
            NULL,           // timeout
            0,              // SizeLimit
            &searchResult
        );
    } else {
        result = WLDAP32$ldap_search_s(
            ld,
            searchBase,
            LDAP_SCOPE_SUBTREE,
            "(objectClass=computer)",
            attrs,
            0,
            &searchResult
        );
    }

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for computers");
        PrintLdapError("Search computers", result);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    int compCount = WLDAP32$ldap_count_entries(ld, searchResult);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d computer(s):\n", compCount);

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    while (entry != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "===================================");
        
        // Display all requested attributes
        for (int i = 0; i < attrCount; i++) {
            DisplayAttributeValue(ld, entry, attrs[i]);
        }

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
