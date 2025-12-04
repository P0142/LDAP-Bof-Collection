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

    // Search for computer objects
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "sAMAccountName", "distinguishedName", "operatingSystem", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        searchBase,
        LDAP_SCOPE_SUBTREE,
        "(objectClass=computer)",
        attrs,
        0,
        &searchResult
    );

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
    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-30s %s", "sAMAccountName", "OperatingSystem", "DistinguishedName");
    BeaconPrintf(CALLBACK_OUTPUT, "================================================================================");
    while (entry != NULL) {
        char** samValues = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
        char** osValues = WLDAP32$ldap_get_values(ld, entry, "operatingSystem");
        char** dnValues = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");

        char* sam = (samValues && samValues[0]) ? samValues[0] : "";
        char* os = (osValues && osValues[0]) ? osValues[0] : "";
        char* dn = (dnValues && dnValues[0]) ? dnValues[0] : "";

        BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-30s %s", sam, os, dn);

        if (samValues) WLDAP32$ldap_value_free(samValues);
        if (osValues) WLDAP32$ldap_value_free(osValues);
        if (dnValues) WLDAP32$ldap_value_free(dnValues);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
