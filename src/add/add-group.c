#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

// Group type constants
#define GROUP_TYPE_SECURITY_GLOBAL      -2147483646
#define GROUP_TYPE_SECURITY_DOMAIN_LOCAL -2147483644
#define GROUP_TYPE_SECURITY_UNIVERSAL   -2147483640
#define GROUP_TYPE_DIST_GLOBAL          2
#define GROUP_TYPE_DIST_DOMAIN_LOCAL    4
#define GROUP_TYPE_DIST_UNIVERSAL       8

int GetGroupType(const char* typeStr, const char* scopeStr) {
    int isSecurity = 1;
    if (typeStr && MSVCRT$strlen(typeStr) > 0) {
        if (MSVCRT$strcmp(typeStr, "distribution") == 0 || MSVCRT$strcmp(typeStr, "dist") == 0) {
            isSecurity = 0;
        }
    }
    
    if (scopeStr && MSVCRT$strlen(scopeStr) > 0) {
        if (MSVCRT$strcmp(scopeStr, "domainlocal") == 0 || MSVCRT$strcmp(scopeStr, "local") == 0) {
            return isSecurity ? GROUP_TYPE_SECURITY_DOMAIN_LOCAL : GROUP_TYPE_DIST_DOMAIN_LOCAL;
        } else if (MSVCRT$strcmp(scopeStr, "universal") == 0) {
            return isSecurity ? GROUP_TYPE_SECURITY_UNIVERSAL : GROUP_TYPE_DIST_UNIVERSAL;
        }
    }
    
    return isSecurity ? GROUP_TYPE_SECURITY_GLOBAL : GROUP_TYPE_DIST_GLOBAL;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: groupname_or_dn, description, type, scope, ou_path, dc_address, use_ldaps
    char* groupIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isGroupDN = BeaconDataInt(&parser);
    char* description = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* type = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* scope = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* ouPath = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!groupIdentifier || MSVCRT$strlen(groupIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Group name or DN is required");
        return;
    }
    
    int groupType = GetGroupType(type, scope);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting group creation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Group identifier: %s %s", groupIdentifier, isGroupDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Group Type: %d", groupType);
    
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
    
    // Build group DN and extract groupname
    char groupDN[512];
    char groupname[256];
    
    if (isGroupDN) {
        // Use provided DN directly
        MSVCRT$_snprintf(groupDN, sizeof(groupDN), "%s", groupIdentifier);
        
        // Extract CN from DN for sAMAccountName
        char* cnStart = MSVCRT$strstr(groupIdentifier, "CN=");
        if (cnStart) {
            cnStart += 3; // Skip "CN="
            char* cnEnd = MSVCRT$strstr(cnStart, ",");
            if (cnEnd) {
                int cnLen = cnEnd - cnStart;
                if (cnLen > 0 && cnLen < 256) {
                    MSVCRT$memcpy(groupname, cnStart, cnLen);
                    groupname[cnLen] = '\0';
                } else {
                    MSVCRT$strcpy(groupname, cnStart);
                }
            } else {
                MSVCRT$strcpy(groupname, cnStart);
            }
        } else {
            // Fallback: use the entire identifier as groupname
            MSVCRT$strcpy(groupname, groupIdentifier);
        }
    } else {
        // Build DN using provided OU path or default Users container
        MSVCRT$strcpy(groupname, groupIdentifier);
        
        if (ouPath && MSVCRT$strlen(ouPath) > 0) {
            // Use provided OU path
            MSVCRT$_snprintf(groupDN, sizeof(groupDN), "CN=%s,%s", groupname, ouPath);
        } else {
            // Use default Users container
            MSVCRT$_snprintf(groupDN, sizeof(groupDN), "CN=%s,CN=Users,%s", groupname, defaultNC);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target DN: %s", groupDN);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] sAMAccountName: %s", groupname);
    
    // Convert group type to string
    char groupTypeStr[20];
    MSVCRT$_snprintf(groupTypeStr, sizeof(groupTypeStr), "%d", groupType);
    
    // Prepare attributes
    char* objectClass_values[] = { "top", "group", NULL };
    LDAPModA objectClass_mod = { LDAP_MOD_ADD, "objectClass", { .modv_strvals = objectClass_values } };
    
    char* cn_values[] = { groupname, NULL };
    LDAPModA cn_mod = { LDAP_MOD_ADD, "cn", { .modv_strvals = cn_values } };
    
    char* sam_values[] = { groupname, NULL };
    LDAPModA sam_mod = { LDAP_MOD_ADD, "sAMAccountName", { .modv_strvals = sam_values } };
    
    char* groupType_values[] = { groupTypeStr, NULL };
    LDAPModA groupType_mod = { LDAP_MOD_ADD, "groupType", { .modv_strvals = groupType_values } };
    
    LDAPModA desc_mod;
    LDAPModA* attrs[6];
    int attrCount = 0;
    attrs[attrCount++] = &objectClass_mod;
    attrs[attrCount++] = &cn_mod;
    attrs[attrCount++] = &sam_mod;
    attrs[attrCount++] = &groupType_mod;
    
    if (description && MSVCRT$strlen(description) > 0) {
        char* desc_values[] = { description, NULL };
        desc_mod.mod_op = LDAP_MOD_ADD;
        desc_mod.mod_type = "description";
        desc_mod.mod_vals.modv_strvals = desc_values;
        attrs[attrCount++] = &desc_mod;
    }
    
    attrs[attrCount] = NULL;
    
    // Add group
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating group...");
    ULONG result = WLDAP32$ldap_add_s(ld, groupDN, attrs);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created group '%s'", groupname);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s", groupDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] sAMAccountName: %s", groupname);
        
        // Print group type details
        const char* typeDesc = "Unknown";
        switch(groupType) {
            case GROUP_TYPE_SECURITY_GLOBAL:
                typeDesc = "Security - Global";
                break;
            case GROUP_TYPE_SECURITY_DOMAIN_LOCAL:
                typeDesc = "Security - Domain Local";
                break;
            case GROUP_TYPE_SECURITY_UNIVERSAL:
                typeDesc = "Security - Universal";
                break;
            case GROUP_TYPE_DIST_GLOBAL:
                typeDesc = "Distribution - Global";
                break;
            case GROUP_TYPE_DIST_DOMAIN_LOCAL:
                typeDesc = "Distribution - Domain Local";
                break;
            case GROUP_TYPE_DIST_UNIVERSAL:
                typeDesc = "Distribution - Universal";
                break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Group Type: %s (%d)", typeDesc, groupType);
        
        if (description && MSVCRT$strlen(description) > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Description: %s", description);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create group");
        PrintLdapError("Add group", result);
        if (result == LDAP_ALREADY_EXISTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Group already exists");
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax");
        } else if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Target OU does not exist");
        }
    }
    
    // Cleanup
    MSVCRT$free(defaultNC);
    MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}