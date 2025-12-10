#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

// Import ldap_rename_ext_s function (the actual export name)
// ldap_rename_s is a macro that maps to ldap_rename_ext_s
DECLSPEC_IMPORT ULONG WLDAP32$ldap_rename_ext_s(
    LDAP* ld, 
    PCHAR dn, 
    PCHAR newrdn, 
    PCHAR newparent, 
    int deleteoldrdn,
    PLDAPControlA* ServerControls,
    PLDAPControlA* ClientControls
);

// Extract RDN from a full DN
// Returns a newly allocated string with just the "CN=Something" part
char* ExtractRDN(const char* dn) {
    if (!dn || MSVCRT$strlen(dn) == 0) return NULL;
    
    // Find the first comma (end of RDN)
    const char* comma = MSVCRT$strstr(dn, ",");
    
    if (!comma) {
        // No comma found - the entire thing is the RDN
        size_t len = MSVCRT$strlen(dn) + 1;
        char* rdn = (char*)MSVCRT$malloc(len);
        if (rdn) {
            MSVCRT$strcpy(rdn, dn);
        }
        return rdn;
    }
    
    // Extract everything before the comma
    size_t rdnLen = comma - dn;
    char* rdn = (char*)MSVCRT$malloc(rdnLen + 1);
    if (rdn) {
        MSVCRT$memcpy(rdn, dn, rdnLen);
        rdn[rdnLen] = '\0';
    }
    
    return rdn;
}

// Extract parent DN from a full DN
// Returns a newly allocated string with everything after the first comma
char* ExtractParentDN(const char* dn) {
    if (!dn || MSVCRT$strlen(dn) == 0) return NULL;
    
    // Find the first comma
    const char* comma = MSVCRT$strstr(dn, ",");
    
    if (!comma || *(comma + 1) == '\0') {
        // No parent (or comma at end)
        return NULL;
    }
    
    // Skip the comma and extract the rest
    comma++; // Move past the comma
    size_t parentLen = MSVCRT$strlen(comma) + 1;
    char* parent = (char*)MSVCRT$malloc(parentLen);
    if (parent) {
        MSVCRT$strcpy(parent, comma);
    }
    
    return parent;
}

// Extract the CN value from an RDN (without the "CN=" prefix)
// E.g., "CN=User Name" -> "User Name"
char* ExtractCNValue(const char* rdn) {
    if (!rdn || MSVCRT$strlen(rdn) < 4) return NULL;
    
    // Check if it starts with "CN="
    if (MSVCRT$strncmp(rdn, "CN=", 3) != 0) {
        // Not a CN-based RDN, return as-is
        size_t len = MSVCRT$strlen(rdn) + 1;
        char* value = (char*)MSVCRT$malloc(len);
        if (value) {
            MSVCRT$strcpy(value, rdn);
        }
        return value;
    }
    
    // Skip "CN=" and return the rest
    const char* value = rdn + 3;
    size_t len = MSVCRT$strlen(value) + 1;
    char* result = (char*)MSVCRT$malloc(len);
    if (result) {
        MSVCRT$strcpy(result, value);
    }
    
    return result;
}

// Build a new full DN from RDN and parent
char* BuildFullDN(const char* rdn, const char* parentDN) {
    if (!rdn) return NULL;
    
    size_t totalLen = MSVCRT$strlen(rdn) + 1; // RDN + null terminator
    
    if (parentDN && MSVCRT$strlen(parentDN) > 0) {
        totalLen += 1 + MSVCRT$strlen(parentDN); // comma + parent DN
    }
    
    char* fullDN = (char*)MSVCRT$malloc(totalLen);
    if (!fullDN) return NULL;
    
    MSVCRT$strcpy(fullDN, rdn);
    
    if (parentDN && MSVCRT$strlen(parentDN) > 0) {
        MSVCRT$strcat(fullDN, ",");
        MSVCRT$strcat(fullDN, parentDN);
    }
    
    return fullDN;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: source_identifier, is_source_dn, target_ou, new_name,
    // search_ou, dc_address, use_ldaps
    char* sourceIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isSourceDN = BeaconDataInt(&parser);
    char* targetOU = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* newName = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    // Validate required parameters
    if (!sourceIdentifier || MSVCRT$strlen(sourceIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Source object identifier is required");
        return;
    }
    
    // Must have at least one operation: move OR rename
    if ((!targetOU || MSVCRT$strlen(targetOU) == 0) && 
        (!newName || MSVCRT$strlen(newName) == 0)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Must specify target OU and/or new name");
        return;
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
    char* sourceDN = NULL;
    
    if (!isSourceDN) {
        
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Resolve source DN
    if (isSourceDN) {
        // Source identifier is already a DN
        size_t len = MSVCRT$strlen(sourceIdentifier) + 1;
        sourceDN = (char*)MSVCRT$malloc(len);
        if (sourceDN) {
            MSVCRT$strcpy(sourceDN, sourceIdentifier);
        }
    } else {
        // Search for source by sAMAccountName
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        sourceDN = FindObjectDN(ld, sourceIdentifier, searchBase);
        
        if (!sourceDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve source DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Object '%s' not found", sourceIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Extract current RDN and parent from source DN
    char* currentRDN = ExtractRDN(sourceDN);
    char* currentParent = ExtractParentDN(sourceDN);
    
    if (!currentRDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse source DN");
        if (defaultNC) MSVCRT$free(defaultNC);
        if (sourceDN) MSVCRT$free(sourceDN);
        CleanupLDAP(ld);
        return;
    }
    
    // Determine new RDN
    char* newRDN = NULL;
    if (newName && MSVCRT$strlen(newName) > 0) {
        // User specified a new name
        // Check if it already has a prefix (CN=, OU=, etc.)
        if (MSVCRT$strstr(newName, "=")) {
            // Already has a prefix, use as-is
            size_t len = MSVCRT$strlen(newName) + 1;
            newRDN = (char*)MSVCRT$malloc(len);
            if (newRDN) {
                MSVCRT$strcpy(newRDN, newName);
            }
        } else {
            // No prefix, add "CN="
            size_t len = 3 + MSVCRT$strlen(newName) + 1;
            newRDN = (char*)MSVCRT$malloc(len);
            if (newRDN) {
                MSVCRT$_snprintf(newRDN, len, "CN=%s", newName);
            }
        }
    } else {
        // No rename, use current RDN
        size_t len = MSVCRT$strlen(currentRDN) + 1;
        newRDN = (char*)MSVCRT$malloc(len);
        if (newRDN) {
            MSVCRT$strcpy(newRDN, currentRDN);
        }
    }
    
    // Determine new parent
    char* newParent = NULL;
    if (targetOU && MSVCRT$strlen(targetOU) > 0) {
        // User specified a target OU
        size_t len = MSVCRT$strlen(targetOU) + 1;
        newParent = (char*)MSVCRT$malloc(len);
        if (newParent) {
            MSVCRT$strcpy(newParent, targetOU);
        }
    } else {
        // No move, use current parent
        if (currentParent) {
            size_t len = MSVCRT$strlen(currentParent) + 1;
            newParent = (char*)MSVCRT$malloc(len);
            if (newParent) {
                MSVCRT$strcpy(newParent, currentParent);
            }
        }
    }
    
    // Build expected new full DN for display
    char* expectedNewDN = BuildFullDN(newRDN, newParent);
    
    // Determine what operation we're doing
    BOOL isMove = FALSE;
    BOOL isRename = FALSE;
    
    if (targetOU && MSVCRT$strlen(targetOU) > 0) {
        // Check if we're actually changing the parent
        if (!currentParent || MSVCRT$strcmp(currentParent, targetOU) != 0) {
            isMove = TRUE;
        }
    }
    
    if (newName && MSVCRT$strlen(newName) > 0) {
        // Check if we're actually changing the RDN
        if (MSVCRT$strcmp(currentRDN, newRDN) != 0) {
            isRename = TRUE;
        }
    }
    
    if (!isMove && !isRename) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No changes detected - object already at target location with target name");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Current DN: %s", sourceDN);
        goto cleanup;
    }
    
    // Perform the rename/move operation
    // Using ldap_rename_ext_s (the actual function exported by wldap32.dll)
    // Parameters: ld, current DN, new RDN, new parent, deleteoldrdn (1 = yes), 
    //             ServerControls (NULL), ClientControls (NULL)
    ULONG result = WLDAP32$ldap_rename_ext_s(
        ld,
        sourceDN,
        newRDN,
        newParent,
        1,      // deleteoldrdn: 1 = delete old RDN value, 0 = keep it
        NULL,   // ServerControls
        NULL    // ClientControls
    );
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Successfully completed operation!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Old DN: %s", sourceDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] New DN: %s", expectedNewDN ? expectedNewDN : "(unable to construct)");
        
        if (isMove && isRename) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Object moved and renamed successfully");
            
            // Extract the CN value for display
            char* oldName = ExtractCNValue(currentRDN);
            char* newNameValue = ExtractCNValue(newRDN);
            if (oldName && newNameValue) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   Name: %s -> %s", oldName, newNameValue);
            }
            if (oldName) MSVCRT$free(oldName);
            if (newNameValue) MSVCRT$free(newNameValue);
            
            if (currentParent && newParent) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   Location: %s -> %s", currentParent, newParent);
            }
        } else if (isMove) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Object moved successfully");
            if (currentParent && newParent) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   From: %s", currentParent);
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   To:   %s", newParent);
            }
        } else if (isRename) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Object renamed successfully");
            char* oldName = ExtractCNValue(currentRDN);
            char* newNameValue = ExtractCNValue(newRDN);
            if (oldName && newNameValue) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   Old name: %s", oldName);
                BeaconPrintf(CALLBACK_OUTPUT, "[+]   New name: %s", newNameValue);
            }
            if (oldName) MSVCRT$free(oldName);
            if (newNameValue) MSVCRT$free(newNameValue);
        }
        
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to move/rename object");
        PrintLdapError("Move/rename object", result);
        BeaconPrintf(CALLBACK_OUTPUT, "");
        
        // Provide specific error guidance
        if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Target OU does not exist");
            if (newParent) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Verify OU path: %s", newParent);
            }
        } else if (result == LDAP_ALREADY_EXISTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] An object with that name already exists in the target location");
            if (expectedNewDN) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Conflicting DN: %s", expectedNewDN);
            }
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions to move/rename object");
            BeaconPrintf(CALLBACK_ERROR, "[!] Required permissions:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Delete permission on source object");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Create child permission on target OU");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax in target OU");
            if (newParent) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Check DN format: %s", newParent);
            }
        } else if (result == LDAP_OPERATIONS_ERROR) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Operation not permitted");
            BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Trying to move critical system object");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Target OU has restrictions");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Object is part of infrastructure");
        } else if (result == LDAP_CONSTRAINT_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Constraint violation");
            BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Object has child objects (can't move containers with children)");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Target OU doesn't accept this object type");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Domain controller can't complete cross-domain move");
        }
    }
    
cleanup:
    // Cleanup
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (sourceDN) MSVCRT$free(sourceDN);
    if (currentRDN) MSVCRT$free(currentRDN);
    if (currentParent) MSVCRT$free(currentParent);
    if (newRDN) MSVCRT$free(newRDN);
    if (newParent) MSVCRT$free(newParent);
    if (expectedNewDN) MSVCRT$free(expectedNewDN);
    CleanupLDAP(ld);
}