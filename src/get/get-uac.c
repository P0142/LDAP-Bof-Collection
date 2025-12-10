#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char* str, char** endptr, int base);

// UAC flag name to value mapping
typedef struct {
    const char* name;
    DWORD value;
    const char* description;
} UAC_FLAG_MAP;

static const UAC_FLAG_MAP uacFlags[] = {
    {"SCRIPT", UF_SCRIPT, "Logon script executed"},
    {"ACCOUNTDISABLE", UF_ACCOUNTDISABLE, "Account disabled"},
    {"HOMEDIR_REQUIRED", UF_HOMEDIR_REQUIRED, "Home directory required"},
    {"LOCKOUT", UF_LOCKOUT, "Account locked out"},
    {"PASSWD_NOTREQD", UF_PASSWD_NOTREQD, "No password required"},
    {"PASSWD_CANT_CHANGE", UF_PASSWD_CANT_CHANGE, "User cannot change password"},
    {"ENCRYPTED_TEXT_PWD_ALLOWED", UF_ENCRYPTED_TEXT_PWD_ALLOWED, "Reversible encryption enabled"},
    {"TEMP_DUPLICATE_ACCOUNT", UF_TEMP_DUPLICATE_ACCOUNT, "Local user account"},
    {"NORMAL_ACCOUNT", UF_NORMAL_ACCOUNT, "Normal user account"},
    {"INTERDOMAIN_TRUST_ACCOUNT", UF_INTERDOMAIN_TRUST_ACCOUNT, "Interdomain trust account"},
    {"WORKSTATION_TRUST_ACCOUNT", UF_WORKSTATION_TRUST_ACCOUNT, "Computer account"},
    {"SERVER_TRUST_ACCOUNT", UF_SERVER_TRUST_ACCOUNT, "Domain controller account"},
    {"DONT_EXPIRE_PASSWD", UF_DONT_EXPIRE_PASSWD, "Password never expires"},
    {"MNS_LOGON_ACCOUNT", UF_MNS_LOGON_ACCOUNT, "MNS logon account"},
    {"SMARTCARD_REQUIRED", UF_SMARTCARD_REQUIRED, "Smart card required"},
    {"TRUSTED_FOR_DELEGATION", UF_TRUSTED_FOR_DELEGATION, "Trusted for delegation"},
    {"NOT_DELEGATED", UF_NOT_DELEGATED, "Cannot be delegated"},
    {"USE_DES_KEY_ONLY", UF_USE_DES_KEY_ONLY, "DES encryption only"},
    {"DONT_REQ_PREAUTH", UF_DONT_REQ_PREAUTH, "Pre-authentication not required"},
    {"PASSWORD_EXPIRED", UF_PASSWORD_EXPIRED, "Password expired"},
    {"TRUSTED_TO_AUTH_FOR_DELEGATION", UF_TRUSTED_TO_AUTH_FOR_DELEGATION, "Trusted for constrained delegation"},
    {"NO_AUTH_DATA_REQUIRED", UF_NO_AUTH_DATA_REQUIRED, "No Kerberos PAC required"},
    {"PARTIAL_SECRETS_ACCOUNT", UF_PARTIAL_SECRETS_ACCOUNT, "RODC partial secrets"},
    {NULL, 0, NULL}
};

void PrintUACFlags(DWORD uacValue) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Current UAC value: 0x%08X (%lu)", uacValue, uacValue);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Active flags:");

    BOOL foundAny = FALSE;
    for (int i = 0; uacFlags[i].name != NULL; i++) {
        if (uacValue & uacFlags[i].value) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %-35s (0x%08X) - %s",
                        uacFlags[i].name,
                        uacFlags[i].value,
                        uacFlags[i].description);
            foundAny = TRUE;
        }
    }

    if (!foundAny) {
        BeaconPrintf(CALLBACK_OUTPUT, "    (No flags set)");
    }
}

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
            if (defaultNC) MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Query UAC attribute
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "userAccountControl", NULL };

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
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query UAC");
        PrintLdapError("Query UAC", result);
        MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (entry) {
        char** values = WLDAP32$ldap_get_values(ld, entry, "userAccountControl");
        if (values && values[0]) {
            DWORD uacValue = (DWORD)MSVCRT$strtol(values[0], NULL, 10);
            PrintUACFlags(uacValue);
            WLDAP32$ldap_value_free(values);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No userAccountControl attribute found");
        }
    }

    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}
