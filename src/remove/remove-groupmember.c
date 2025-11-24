#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

// Import additional MSVCRT functions needed
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: group_identifier, is_group_dn, member_identifier, is_member_dn, 
    // search_ou, dc_address, use_ldaps
    char* groupIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isGroupDN = BeaconDataInt(&parser);
    char* memberIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isMemberDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!memberIdentifier || MSVCRT$strlen(memberIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Member identifier is required");
        return;
    }
    
    if (!groupIdentifier || MSVCRT$strlen(groupIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Group identifier is required");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting LDAP group membership removal");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Member: %s %s", memberIdentifier, isMemberDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Group: %s %s", groupIdentifier, isGroupDN ? "(DN)" : "(name)");
    
    if (searchOu && MSVCRT$strlen(searchOu) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Search OU: %s", searchOu);
    }
    
    if (dcAddress && MSVCRT$strlen(dcAddress) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Domain Controller: %s", dcAddress);
    }
    
    if (useLdaps) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using LDAPS (port 636)");
    }
    
    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }
    
    // Get default naming context (needed for searches if DN not provided)
    char* defaultNC = NULL;
    char* memberDN = NULL;
    char* groupDN = NULL;
    
    if (!isMemberDN || !isGroupDN) {
        
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Default naming context: %s", defaultNC);
    }
    
    // Resolve member DN
    if (isMemberDN) {
        // Member identifier is already a DN
        size_t len = MSVCRT$strlen(memberIdentifier) + 1;
        memberDN = (char*)MSVCRT$malloc(len);
        if (memberDN) {
            MSVCRT$strcpy(memberDN, memberIdentifier);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided member DN: %s", memberDN);
    } else {
        // Search for member by sAMAccountName
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Resolving member DN...");
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        memberDN = FindObjectDN(ld, memberIdentifier, searchBase);
        
        if (!memberDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve member DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Member '%s' not found", memberIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Member DN: %s", memberDN);
    }
    
    // Resolve group DN
    if (isGroupDN) {
        // Group identifier is already a DN
        size_t len = MSVCRT$strlen(groupIdentifier) + 1;
        groupDN = (char*)MSVCRT$malloc(len);
        if (groupDN) {
            MSVCRT$strcpy(groupDN, groupIdentifier);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided group DN: %s", groupDN);
    } else {
        // Search for group by sAMAccountName
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Resolving group DN...");
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        groupDN = FindObjectDN(ld, groupIdentifier, searchBase);
        
        if (!groupDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve group DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Group '%s' not found", groupIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            MSVCRT$free(memberDN);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Group DN: %s", groupDN);
    }
    
    // Prepare LDAP modification to remove member
    char* member_values[] = { memberDN, NULL };
    LDAPModA member_mod;
    member_mod.mod_op = LDAP_MOD_DELETE;
    member_mod.mod_type = "member";
    member_mod.mod_vals.modv_strvals = member_values;
    
    LDAPModA* mods[] = { &member_mod, NULL };
    
    // Apply the modification
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Removing member from group...");
    ULONG result = WLDAP32$ldap_modify_s(ld, groupDN, mods);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully removed member from group");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Member DN: %s", memberDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Group DN: %s", groupDN);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove member from group");
        PrintLdapError("Modify group", result);
        
        // Provide helpful hints
        if (result == LDAP_NO_SUCH_ATTRIBUTE) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Member is not in the group");
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions to modify group membership");
        } else if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Group or member object does not exist");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax");
        }
    }
    
    // Cleanup
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (memberDN) MSVCRT$free(memberDN);
    if (groupDN) MSVCRT$free(groupDN);
    CleanupLDAP(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}