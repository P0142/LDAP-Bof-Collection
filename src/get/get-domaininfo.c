#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: dc_address, use_ldaps
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Gathering domain information");

    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }

    // Query rootDSE for domain info
    LDAPMessage* searchResult = NULL;
    char* attrs[] = {
        "defaultNamingContext",
        "rootDomainNamingContext",
        "configurationNamingContext",
        "schemaNamingContext",
        "dnsHostName",
        "serverName",
        "ldapServiceName",
        "forestFunctionality",
        "domainFunctionality",
        "domainControllerFunctionality",
        "supportedLDAPVersion",
        "currentTime",
        "highestCommittedUSN",
        NULL
    };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        "",
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query rootDSE");
        PrintLdapError("Query rootDSE", result);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Domain Information:");
        BeaconPrintf(CALLBACK_OUTPUT, "=======================");

        // Print each attribute
        for (int i = 0; attrs[i] != NULL; i++) {
            char** values = WLDAP32$ldap_get_values(ld, entry, attrs[i]);
            if (values && values[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "%-35s : %s", attrs[i], values[0]);
                WLDAP32$ldap_value_free(values);
            }
        }
    }

    WLDAP32$ldap_msgfree(searchResult);

    // Get default naming context for additional queries
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (defaultNC) {
        // Count users, computers, groups
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Object Counts:");
        BeaconPrintf(CALLBACK_OUTPUT, "==================");

        // Count users
        LDAPMessage* countResult = NULL;
        result = WLDAP32$ldap_search_s(ld, defaultNC, LDAP_SCOPE_SUBTREE,
            "(&(objectClass=user)(objectCategory=person))", NULL, 1, &countResult);
        if (result == LDAP_SUCCESS) {
            int count = WLDAP32$ldap_count_entries(ld, countResult);
            BeaconPrintf(CALLBACK_OUTPUT, "%-35s : %d", "Users", count);
            WLDAP32$ldap_msgfree(countResult);
        }

        // Count computers
        result = WLDAP32$ldap_search_s(ld, defaultNC, LDAP_SCOPE_SUBTREE,
            "(objectClass=computer)", NULL, 1, &countResult);
        if (result == LDAP_SUCCESS) {
            int count = WLDAP32$ldap_count_entries(ld, countResult);
            BeaconPrintf(CALLBACK_OUTPUT, "%-35s : %d", "Computers", count);
            WLDAP32$ldap_msgfree(countResult);
        }

        // Count groups
        result = WLDAP32$ldap_search_s(ld, defaultNC, LDAP_SCOPE_SUBTREE,
            "(objectClass=group)", NULL, 1, &countResult);
        if (result == LDAP_SUCCESS) {
            int count = WLDAP32$ldap_count_entries(ld, countResult);
            BeaconPrintf(CALLBACK_OUTPUT, "%-35s : %d", "Groups", count);
            WLDAP32$ldap_msgfree(countResult);
        }

        // Count OUs
        result = WLDAP32$ldap_search_s(ld, defaultNC, LDAP_SCOPE_SUBTREE,
            "(objectClass=organizationalUnit)", NULL, 1, &countResult);
        if (result == LDAP_SUCCESS) {
            int count = WLDAP32$ldap_count_entries(ld, countResult);
            BeaconPrintf(CALLBACK_OUTPUT, "%-35s : %d", "Organizational Units", count);
            WLDAP32$ldap_msgfree(countResult);
        }

        MSVCRT$free(defaultNC);
    }

    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Operation complete");
}
