#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: target_identifier, is_dn, search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
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
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Query msDS-AllowedToActOnBehalfOfOtherIdentity attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "msDS-AllowedToActOnBehalfOfOtherIdentity", NULL };

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
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query RBCD attribute");
        PrintLdapError("Query RBCD", result);
        MSVCRT$free(targetDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        struct berval** values = WLDAP32$ldap_get_values_len(ld, entry, "msDS-AllowedToActOnBehalfOfOtherIdentity");
        if (values && values[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] RBCD Configuration Found:");
            BeaconPrintf(CALLBACK_OUTPUT, "==============================");
            BeaconPrintf(CALLBACK_OUTPUT, "[*] msDS-AllowedToActOnBehalfOfOtherIdentity is set (%d bytes)", values[0]->bv_len);

            // Parse the security descriptor stored in this attribute
            PSD_INFO sdInfo = ParseSecurityDescriptor((BYTE*)values[0]->bv_val, values[0]->bv_len);
            if (sdInfo) {
                BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Principals allowed to delegate:");
                if (sdInfo->DaclAces) {
                    for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
                        PPARSED_ACE_INFO ace = &sdInfo->DaclAces[i];
                        if (ace->TrusteeSid) {
                            // Try to resolve the SID to a name
                            char* trusteeName = ResolveSidToName(ld, ace->TrusteeSid, defaultNC);
                            if (trusteeName) {
                                BeaconPrintf(CALLBACK_OUTPUT, "    [%d] %s (%s)", i, trusteeName, ace->TrusteeSid);
                                MSVCRT$free(trusteeName);
                            } else {
                                BeaconPrintf(CALLBACK_OUTPUT, "    [%d] %s", i, ace->TrusteeSid);
                            }
                        }
                    }
                }
                FreeSecurityDescriptorInfo(sdInfo);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Could not parse RBCD security descriptor");
            }

            WLDAP32$ldap_value_free_len(values);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] No RBCD configuration found");
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(targetDN);
    MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
