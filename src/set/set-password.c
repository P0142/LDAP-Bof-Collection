#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

// Import additional MSVCRT functions needed
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: user_identifier, is_user_dn, old_password, new_password, 
    // search_ou, dc_address, use_ldaps
    char* userIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isUserDN = BeaconDataInt(&parser);
    char* newPassword = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* oldPassword = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!userIdentifier || MSVCRT$strlen(userIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] User identifier is required");
        return;
    }
    
    if (!newPassword || MSVCRT$strlen(newPassword) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] New password is required");
        return;
    }
    
    BOOL hasOldPassword = (oldPassword && MSVCRT$strlen(oldPassword) > 0);
    BOOL isAdminReset = !hasOldPassword;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting LDAP password operation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] User: %s %s", userIdentifier, isUserDN ? "(DN)" : "(name)");
    
    if (isAdminReset) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation type: Administrative password reset (requires admin rights)");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] LDAPS required - will use port 636");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation type: User password change");
    }
    
    if (searchOu && MSVCRT$strlen(searchOu) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Search OU: %s", searchOu);
    }
    
    if (dcAddress && MSVCRT$strlen(dcAddress) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Domain Controller: %s", dcAddress);
    }
    
    // Force LDAPS for admin reset OR if explicitly requested
    BOOL requireLdaps = isAdminReset || useLdaps;
    
    if (requireLdaps) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using LDAPS (port 636)");
    }
    
    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }
    
    // Get default naming context - will build from hostname if possible
    char* userDN = NULL;
    char* defaultNC = NULL;
    if (!isUserDN) {
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Resolve user DN
    if (isUserDN) {
        // User identifier is already a DN
        size_t len = MSVCRT$strlen(userIdentifier) + 1;
        userDN = (char*)MSVCRT$malloc(len);
        if (userDN) {
            MSVCRT$strcpy(userDN, userIdentifier);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided user DN: %s", userDN);
    } else {
        // Search for user by sAMAccountName
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Resolving user DN...");
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        userDN = FindObjectDN(ld, userIdentifier, searchBase);
        
        if (!userDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve user DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] User '%s' not found", userIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User DN: %s", userDN);
    }
    
    // Encode passwords
    BERVAL* oldPasswordBerval = NULL;
    BERVAL* newPasswordBerval = NULL;
    
    if (!isAdminReset) {
        oldPasswordBerval = EncodePassword(oldPassword);
        if (!oldPasswordBerval) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to encode old password");
            if (defaultNC) MSVCRT$free(defaultNC);
            MSVCRT$free(userDN);
            CleanupLDAP(ld);
            return;
        }
    }
    
    newPasswordBerval = EncodePassword(newPassword);
    if (!newPasswordBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to encode new password");
        if (oldPasswordBerval) {
            MSVCRT$free(oldPasswordBerval->bv_val);
            MSVCRT$free(oldPasswordBerval);
        }
        if (defaultNC) MSVCRT$free(defaultNC);
        MSVCRT$free(userDN);
        CleanupLDAP(ld);
        return;
    }
    
    // Prepare LDAP modification
    ULONG result;
    
    if (isAdminReset) {
        // Administrative reset: use LDAP_MOD_REPLACE
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Performing administrative password reset...");
        
        BERVAL* password_bervals[] = { newPasswordBerval, NULL };
        LDAPModA password_mod;
        password_mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
        password_mod.mod_type = "unicodePwd";
        password_mod.mod_vals.modv_bvals = password_bervals;
        
        LDAPModA* mods[] = { &password_mod, NULL };
        
        result = WLDAP32$ldap_modify_s(ld, userDN, mods);
    } else {
        // User password change: delete old, add new
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Performing user password change...");
        
        BERVAL* old_password_bervals[] = { oldPasswordBerval, NULL };
        LDAPModA old_password_mod;
        old_password_mod.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
        old_password_mod.mod_type = "unicodePwd";
        old_password_mod.mod_vals.modv_bvals = old_password_bervals;
        
        BERVAL* new_password_bervals[] = { newPasswordBerval, NULL };
        LDAPModA new_password_mod;
        new_password_mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
        new_password_mod.mod_type = "unicodePwd";
        new_password_mod.mod_vals.modv_bvals = new_password_bervals;
        
        LDAPModA* mods[] = { &old_password_mod, &new_password_mod, NULL };
        
        result = WLDAP32$ldap_modify_s(ld, userDN, mods);
    }
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Password operation successful");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] User DN: %s", userDN);
        if (isAdminReset) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Password reset by administrator");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Password changed by user");
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Password operation failed");
        PrintLdapError("Password modification", result);
        
        // Provide helpful hints
        if (result == LDAP_INSUFFICIENT_RIGHTS) {
            if (isAdminReset) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions - admin rights required for password reset");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions or incorrect old password");
            }
        } else if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] User object does not exist");
        } else if (result == LDAP_CONSTRAINT_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] New password does not meet domain password policy requirements");
        } else if (result == LDAP_INVALID_CREDENTIALS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid old password");
        }
    }
    
    // Cleanup
    if (oldPasswordBerval) {
        MSVCRT$free(oldPasswordBerval->bv_val);
        MSVCRT$free(oldPasswordBerval);
    }
    if (newPasswordBerval) {
        MSVCRT$free(newPasswordBerval->bv_val);
        MSVCRT$free(newPasswordBerval);
    }
    if (defaultNC) MSVCRT$free(defaultNC);
    if (userDN) MSVCRT$free(userDN);
    CleanupLDAP(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}