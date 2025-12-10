#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: dc_address, use_ldaps
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

    // Query domain object for ms-DS-MachineAccountQuota attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "ms-DS-MachineAccountQuota", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        defaultNC,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query machine account quota");
        PrintLdapError("Query MAQ", result);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** maqValues = WLDAP32$ldap_get_values(ld, entry, "ms-DS-MachineAccountQuota");
        if (maqValues && maqValues[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Machine Account Quota (ms-DS-MachineAccountQuota): %s", maqValues[0]);
            WLDAP32$ldap_value_free(maqValues);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Machine Account Quota attribute not found or not set");
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] No results returned");
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
