#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: username (or DN), password, firstname, lastname, email, disabled, 
    // ou_path, dc_address, use_ldaps
    char* userIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isUserDN = BeaconDataInt(&parser);
    char* password = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* firstname = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* lastname = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* email = ValidateInput(BeaconDataExtract(&parser, NULL));
    int disabled = BeaconDataInt(&parser);
    char* ouPath = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!userIdentifier || MSVCRT$strlen(userIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Username or DN is required");
        return;
    }
    
    if (!password || MSVCRT$strlen(password) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Password is required");
        return;
    }
    
    // Force LDAPS if password provided
    BOOL requireLdaps = (password && MSVCRT$strlen(password) > 0) || useLdaps;
    
    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }
    
    // Get default naming context - will build from hostname if possible
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }
    
    // Build user DN and extract username
    char userDN[512];
    char username[256];
    
    if (isUserDN) {
        // Use provided DN directly
        MSVCRT$_snprintf(userDN, sizeof(userDN), "%s", userIdentifier);
        
        // Extract CN from DN for sAMAccountName
        char* cnStart = MSVCRT$strstr(userIdentifier, "CN=");
        if (cnStart) {
            cnStart += 3; // Skip "CN="
            char* cnEnd = MSVCRT$strstr(cnStart, ",");
            if (cnEnd) {
                int cnLen = cnEnd - cnStart;
                if (cnLen > 0 && cnLen < 256) {
                    MSVCRT$memcpy(username, cnStart, cnLen);
                    username[cnLen] = '\0';
                } else {
                    MSVCRT$strcpy(username, cnStart);
                }
            } else {
                MSVCRT$strcpy(username, cnStart);
            }
        } else {
            // Fallback: use the entire identifier as username
            MSVCRT$strcpy(username, userIdentifier);
        }
    } else {
        // Build DN using provided OU path or default Users container
        MSVCRT$strcpy(username, userIdentifier);
        
        if (ouPath && MSVCRT$strlen(ouPath) > 0) {
            // Use provided OU path
            MSVCRT$_snprintf(userDN, sizeof(userDN), "CN=%s,%s", username, ouPath);
        } else {
            // Use default Users container
            MSVCRT$_snprintf(userDN, sizeof(userDN), "CN=%s,CN=Users,%s", username, defaultNC);
        }
    }
    
    // Build UPN (username@domain)
    char upn[256];
    char* dcPtr = defaultNC;
    char domain[256] = {0};
    int domainPos = 0;
    int firstDC = 1;
    
    while (*dcPtr && domainPos < 255) {
        if (dcPtr[0] == 'D' && dcPtr[1] == 'C' && dcPtr[2] == '=') {
            dcPtr += 3;
            if (!firstDC) domain[domainPos++] = '.';
            firstDC = 0;
            while (*dcPtr && *dcPtr != ',' && domainPos < 255) {
                char ch = *dcPtr;
                if (ch >= 'A' && ch <= 'Z') ch += 32; // lowercase
                domain[domainPos++] = ch;
                dcPtr++;
            }
        } else {
            dcPtr++;
        }
    }
    domain[domainPos] = '\0';
    MSVCRT$_snprintf(upn, sizeof(upn), "%s@%s", username, domain);
    
    // Prepare attributes
    char* objectClass_values[] = { "top", "person", "organizationalPerson", "user", NULL };
    LDAPModA objectClass_mod = { LDAP_MOD_ADD, "objectClass", { .modv_strvals = objectClass_values } };
    
    char* cn_values[] = { username, NULL };
    LDAPModA cn_mod = { LDAP_MOD_ADD, "cn", { .modv_strvals = cn_values } };
    
    char* sam_values[] = { username, NULL };
    LDAPModA sam_mod = { LDAP_MOD_ADD, "sAMAccountName", { .modv_strvals = sam_values } };
    
    char* upn_values[] = { upn, NULL };
    LDAPModA upn_mod = { LDAP_MOD_ADD, "userPrincipalName", { .modv_strvals = upn_values } };
    
    char* uac_values[] = { disabled ? "514" : "512", NULL };
    LDAPModA uac_mod = { LDAP_MOD_ADD, "userAccountControl", { .modv_strvals = uac_values } };
    
    // Optional attributes
    LDAPModA givenName_mod, sn_mod, mail_mod, password_mod;
    BERVAL* encodedPassword = NULL;
    BERVAL* password_bervals[2] = { NULL, NULL };
    
    LDAPModA* attrs[10];
    int attrCount = 0;
    attrs[attrCount++] = &objectClass_mod;
    attrs[attrCount++] = &cn_mod;
    attrs[attrCount++] = &sam_mod;
    attrs[attrCount++] = &upn_mod;
    attrs[attrCount++] = &uac_mod;
    
    if (firstname && MSVCRT$strlen(firstname) > 0) {
        char* given_values[] = { firstname, NULL };
        givenName_mod.mod_op = LDAP_MOD_ADD;
        givenName_mod.mod_type = "givenName";
        givenName_mod.mod_vals.modv_strvals = given_values;
        attrs[attrCount++] = &givenName_mod;
    }
    
    if (lastname && MSVCRT$strlen(lastname) > 0) {
        char* sn_values[] = { lastname, NULL };
        sn_mod.mod_op = LDAP_MOD_ADD;
        sn_mod.mod_type = "sn";
        sn_mod.mod_vals.modv_strvals = sn_values;
        attrs[attrCount++] = &sn_mod;
    }
    
    if (email && MSVCRT$strlen(email) > 0) {
        char* mail_values[] = { email, NULL };
        mail_mod.mod_op = LDAP_MOD_ADD;
        mail_mod.mod_type = "mail";
        mail_mod.mod_vals.modv_strvals = mail_values;
        attrs[attrCount++] = &mail_mod;
    }
    
    if (password && MSVCRT$strlen(password) > 0) {
        encodedPassword = EncodePassword(password);
        if (encodedPassword) {
            password_bervals[0] = encodedPassword;
            password_mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
            password_mod.mod_type = "unicodePwd";
            password_mod.mod_vals.modv_bvals = password_bervals;
            attrs[attrCount++] = &password_mod;
        }
    }
    
    attrs[attrCount] = NULL;
    
    // Add user
    ULONG result = WLDAP32$ldap_add_s(ld, userDN, attrs);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created user '%s'", username);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s", userDN);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create user");
        PrintLdapError("Add user", result);
        if (result == LDAP_ALREADY_EXISTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] User already exists");
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions");
        }
    }
    
    // Cleanup
    if (encodedPassword) {
        MSVCRT$free(encodedPassword->bv_val);
        MSVCRT$free(encodedPassword);
    }
    MSVCRT$free(defaultNC);
    MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}