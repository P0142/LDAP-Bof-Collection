#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: search_ou, dc_address, use_ldaps, detailed
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    int detailed = BeaconDataInt(&parser);

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

    char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;

    // Search for objects - we'll check each one for write access
    // Focus on high-value targets: users, computers, groups
    LDAPMessage* searchResult = NULL;
    char* attrs[] = { 
        "distinguishedName", 
        "objectClass",
        "allowedAttributesEffective",  // This shows what the current user can write
        "allowedChildClassesEffective", // This shows what child objects can be created
        NULL 
    };

    // Search for users and computers (objectCategory=person catches users)
    char* filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))";

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        searchBase,
        LDAP_SCOPE_SUBTREE,
        filter,
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for objects");
        PrintLdapError("Search objects", result);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    int totalCount = WLDAP32$ldap_count_entries(ld, searchResult);
    int writableCount = 0;

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    while (entry != NULL) {
        char** dnValues = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");
        char** effectiveAttrs = WLDAP32$ldap_get_values(ld, entry, "allowedAttributesEffective");
        char** childClasses = WLDAP32$ldap_get_values(ld, entry, "allowedChildClassesEffective");

        BOOL hasWritePerms = (effectiveAttrs && effectiveAttrs[0]);
        BOOL hasCreateChild = (childClasses && childClasses[0]);
        
        // If the object has writable attributes OR createChild permissions, it's interesting
        if (hasWritePerms || hasCreateChild) {
            writableCount++;
            
            if (detailed) {
                // Show DN
                if (dnValues && dnValues[0]) {
                    BeaconPrintf(CALLBACK_OUTPUT, "distinguishedName: %s", dnValues[0]);
                }
                
                // Show all writable attributes
                if (hasWritePerms) {
                    int i = 0;
                    while (effectiveAttrs[i] != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "%s: WRITE", effectiveAttrs[i]);
                        i++;
                    }
                }
                
                // Show all creatable child classes
                if (hasCreateChild) {
                    int i = 0;
                    while (childClasses[i] != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "%s: CREATE_CHILD", childClasses[i]);
                        i++;
                    }
                }
                
                BeaconPrintf(CALLBACK_OUTPUT, "\n");  // Blank line between objects
            } else {
                // Just show DN and permission type(s)
                if (dnValues && dnValues[0]) {
                    BeaconPrintf(CALLBACK_OUTPUT, "distinguishedName: %s", dnValues[0]);
                    
                    // Show which permission types apply
                    if (hasWritePerms && hasCreateChild) {
                        BeaconPrintf(CALLBACK_OUTPUT, "permission: WRITE, CREATE_CHILD");
                    } else if (hasWritePerms) {
                        BeaconPrintf(CALLBACK_OUTPUT, "permission: WRITE");
                    } else if (hasCreateChild) {
                        BeaconPrintf(CALLBACK_OUTPUT, "permission: CREATE_CHILD");
                    }
                    
                    BeaconPrintf(CALLBACK_OUTPUT, "\n");  // Blank line between objects
                }
            }
        }
        
        if (dnValues) WLDAP32$ldap_value_free(dnValues);
        if (effectiveAttrs) WLDAP32$ldap_value_free(effectiveAttrs);
        if (childClasses) WLDAP32$ldap_value_free(childClasses);
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }
    
    WLDAP32$ldap_msgfree(searchResult);
    MSVCRT$free(defaultNC);
    MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d objects with write permissions", writableCount);
}
