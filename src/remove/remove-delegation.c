#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* spn = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }

    if (!spn || MSVCRT$strlen(spn) == 0) {
        return;
    }

    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }

    char* defaultNC = NULL;
    if (!isTargetDN) {
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    char* targetDN = NULL;
    if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) MSVCRT$strcpy(targetDN, targetIdentifier);
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", targetIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    char* spn_values[] = { spn, NULL };
    LDAPModA spn_mod;
    spn_mod.mod_op = LDAP_MOD_DELETE;
    spn_mod.mod_type = "msDS-AllowedToDelegateTo";
    spn_mod.mod_vals.modv_strvals = spn_values;

    LDAPModA* mods[] = { &spn_mod, NULL };

    ULONG result = WLDAP32$ldap_modify_s(ld, targetDN, mods);

    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully removed delegation SPN '%s'", spn);
    } else if (result == LDAP_NO_SUCH_ATTRIBUTE) {
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove delegation");
        PrintLdapError("Remove delegation", result);
    }

    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
