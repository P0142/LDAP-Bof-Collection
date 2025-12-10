#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: ou_name_or_dn, is_dn, description, parent_ou, dc_address, use_ldaps
    char* ouIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isOuDN = BeaconDataInt(&parser);
    char* description = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* parentOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!ouIdentifier || MSVCRT$strlen(ouIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OU name or DN is required");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OU identifier: %s %s", ouIdentifier, isOuDN ? "(DN)" : "(name)");
    
    if (description && MSVCRT$strlen(description) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Description: %s", description);
    }
    
    if (parentOu && MSVCRT$strlen(parentOu) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Parent OU: %s", parentOu);
    }
    
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
    
    // Build OU DN
    char ouDN[512];
    char ouName[256];
    
    if (isOuDN) {
        // Use provided DN directly
        MSVCRT$_snprintf(ouDN, sizeof(ouDN), "%s", ouIdentifier);
        
        // Extract OU name from DN for display
        char* ouStart = MSVCRT$strstr(ouIdentifier, "OU=");
        if (ouStart) {
            ouStart += 3; // Skip "OU="
            char* ouEnd = MSVCRT$strstr(ouStart, ",");
            if (ouEnd) {
                int ouLen = ouEnd - ouStart;
                if (ouLen > 0 && ouLen < 256) {
                    MSVCRT$memcpy(ouName, ouStart, ouLen);
                    ouName[ouLen] = '\0';
                } else {
                    MSVCRT$strcpy(ouName, ouStart);
                }
            } else {
                MSVCRT$strcpy(ouName, ouStart);
            }
        } else {
            // Fallback: use the entire identifier as name
            MSVCRT$strcpy(ouName, ouIdentifier);
        }
    } else {
        // Build DN using provided OU name and parent OU or default NC
        MSVCRT$strcpy(ouName, ouIdentifier);
        
        if (parentOu && MSVCRT$strlen(parentOu) > 0) {
            // Use provided parent OU
            MSVCRT$_snprintf(ouDN, sizeof(ouDN), "OU=%s,%s", ouName, parentOu);
        } else {
            // Use domain root as parent
            MSVCRT$_snprintf(ouDN, sizeof(ouDN), "OU=%s,%s", ouName, defaultNC);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] OU name: %s", ouName);
    
    // Prepare attributes for OU creation
    char* objectClass_values[] = { "top", "organizationalUnit", NULL };
    LDAPModA objectClass_mod = { LDAP_MOD_ADD, "objectClass", { .modv_strvals = objectClass_values } };
    
    char* ou_values[] = { ouName, NULL };
    LDAPModA ou_mod = { LDAP_MOD_ADD, "ou", { .modv_strvals = ou_values } };
    
    // Optional description attribute
    LDAPModA description_mod;
    char* description_values[2] = { NULL, NULL };
    
    int attrCount = 2; // objectClass and ou
    LDAPModA* attrs[4]; // objectClass, ou, optional description, NULL
    
    attrs[0] = &objectClass_mod;
    attrs[1] = &ou_mod;
    
    if (description && MSVCRT$strlen(description) > 0) {
        description_values[0] = description;
        description_mod.mod_op = LDAP_MOD_ADD;
        description_mod.mod_type = "description";
        description_mod.mod_vals.modv_strvals = description_values;
        attrs[attrCount++] = &description_mod;
    }
    
    attrs[attrCount] = NULL;
    
    // Create the OU
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating organizational unit...");
    ULONG result = WLDAP32$ldap_add_s(ld, ouDN, attrs);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created OU!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] OU Name: %s", ouName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s", ouDN);
        
        if (description && MSVCRT$strlen(description) > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Description: %s", description);
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] The OU can now be used to organize objects:");
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   ldap add-user username password -ou \"%s\"", ouDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   ldap add-computer computername -ou \"%s\"", ouDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   ldap move-object object -ou \"%s\"", ouDN);
        
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create OU");
        PrintLdapError("Create OU", result);
        
        if (result == LDAP_ALREADY_EXISTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] OU already exists at this location");
            BeaconPrintf(CALLBACK_ERROR, "[!] DN: %s", ouDN);
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions to create OU");
            BeaconPrintf(CALLBACK_ERROR, "[!] Required permission: Create Organizational Unit objects");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax");
            if (parentOu && MSVCRT$strlen(parentOu) > 0) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Check parent OU format: %s", parentOu);
            }
        } else if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Parent container does not exist");
            if (parentOu && MSVCRT$strlen(parentOu) > 0) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Parent OU: %s", parentOu);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] Domain root: %s", defaultNC);
            }
        } else if (result == LDAP_CONSTRAINT_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Constraint violation");
            BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - OU name contains invalid characters");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Parent container doesn't accept OUs");
        } else if (result == LDAP_OBJECT_CLASS_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Object class violation");
            BeaconPrintf(CALLBACK_ERROR, "[!] Parent container may not accept organizational units");
        }
    }
    
    // Cleanup
    MSVCRT$free(defaultNC);
    MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}