#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: search_ou, dc_address, use_ldaps
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

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

    // Search for user objects
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "sAMAccountName", "distinguishedName", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        searchBase,
        LDAP_SCOPE_SUBTREE,
        "(&(objectClass=user)(objectCategory=person))",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for users");
        PrintLdapError("Search users", result);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    int userCount = WLDAP32$ldap_count_entries(ld, searchResult);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d user(s):\n", userCount);

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    BeaconPrintf(CALLBACK_OUTPUT, "%-20s %s", "sAMAccountName", "DistinguishedName");
    BeaconPrintf(CALLBACK_OUTPUT, "===================================");
    while (entry != NULL) {
        char** samValues = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
        char** dnValues = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");

        if (samValues && samValues[0] && dnValues) {
            BeaconPrintf(CALLBACK_OUTPUT, "%-20s %s", samValues[0], dnValues[0]);
        }

        if (samValues) WLDAP32$ldap_value_free(samValues);
        if (dnValues) WLDAP32$ldap_value_free(dnValues);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
