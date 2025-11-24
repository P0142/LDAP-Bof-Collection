#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: user_identifier, is_dn, search_ou, dc_address, use_ldaps
    char* userIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isUserDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!userIdentifier || MSVCRT$strlen(userIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] User identifier is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting user group enumeration");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target user: %s %s", userIdentifier, isUserDN ? "(DN)" : "(name)");

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

    // Resolve user DN
    char* userDN = NULL;
    if (isUserDN) {
        size_t len = MSVCRT$strlen(userIdentifier) + 1;
        userDN = (char*)MSVCRT$malloc(len);
        if (userDN) {
            MSVCRT$strcpy(userDN, userIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        userDN = FindObjectDN(ld, userIdentifier, searchBase);
        if (!userDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] User '%s' not found", userIdentifier);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User DN: %s", userDN);
    }

    // Query the user's memberOf attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "memberOf", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        userDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query user groups");
        PrintLdapError("Query memberOf", result);
        MSVCRT$free(userDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** memberOfValues = WLDAP32$ldap_get_values(ld, entry, "memberOf");
        if (memberOfValues) {
            int groupCount = WLDAP32$ldap_count_values(memberOfValues);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] User is member of %d group(s):\n", groupCount);
            BeaconPrintf(CALLBACK_OUTPUT, "Group DN");
            BeaconPrintf(CALLBACK_OUTPUT, "========");
            for (int i = 0; memberOfValues[i] != NULL; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s", memberOfValues[i]);
            }
            WLDAP32$ldap_value_free(memberOfValues);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] User is not a member of any groups (or only primary group)");
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(userDN);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}
