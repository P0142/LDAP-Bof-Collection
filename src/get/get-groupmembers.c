#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: group_identifier, is_dn, search_ou, dc_address
    char* groupIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isGroupDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));

    if (!groupIdentifier || MSVCRT$strlen(groupIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Group identifier is required");
        return;
    }

    // Initialize LDAP connection (always use regular LDAP for queries)
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, FALSE, &dcHostname);
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

    // Resolve group DN
    char* groupDN = NULL;
    if (isGroupDN) {
        size_t len = MSVCRT$strlen(groupIdentifier) + 1;
        groupDN = (char*)MSVCRT$malloc(len);
        if (groupDN) {
            MSVCRT$strcpy(groupDN, groupIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        groupDN = FindObjectDN(ld, groupIdentifier, searchBase);
        if (!groupDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Group '%s' not found", groupIdentifier);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Group DN: %s", groupDN);
    }

    // Query the group's member attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "member", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        groupDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query group members");
        PrintLdapError("Query member", result);
        MSVCRT$free(groupDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** memberValues = WLDAP32$ldap_get_values(ld, entry, "member");
        if (memberValues) {
            int memberCount = WLDAP32$ldap_count_values(memberValues);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Group has %d member(s):\n", memberCount);
            BeaconPrintf(CALLBACK_OUTPUT, "Member DN");
            BeaconPrintf(CALLBACK_OUTPUT, "=========");
            for (int i = 0; memberValues[i] != NULL; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s", memberValues[i]);
            }
            WLDAP32$ldap_value_free(memberValues);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Group has no members");
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(groupDN);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
