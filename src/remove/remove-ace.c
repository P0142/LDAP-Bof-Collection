#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void* buffer1, const void* buffer2, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);

// Helper function to compare GUIDs
BOOL AreGuidsEqual(GUID* guid1, GUID* guid2) {
    if (!guid1 || !guid2) return FALSE;
    return (MSVCRT$memcmp(guid1, guid2, sizeof(GUID)) == 0);
}

// Helper function to check if an access mask represents an expanded generic right
// Windows expands generic rights to specific rights when writing to AD
BOOL IsExpandedGenericRight(ACCESS_MASK aceMask, ACCESS_MASK genericRight) {
    // Define expanded forms for each generic right in Active Directory
    
    // GENERIC_ALL (0x10000000) expands to:
    // DELETE | WRITE_DACL | WRITE_OWNER | READ_CONTROL | 
    // CREATE_CHILD | DELETE_CHILD | READ_PROP | WRITE_PROP | EXTENDED_RIGHT
    const ACCESS_MASK EXPANDED_GENERIC_ALL = 0x000F0133;
    const ACCESS_MASK EXPANDED_GENERIC_ALL_ALT = 0x000F01FF;  // Some variations
    const ACCESS_MASK GENERIC_ALL_CORE_RIGHTS = 
        DELETE_ACCESS |                 // 0x00010000
        WRITE_DACL |                    // 0x00040000
        WRITE_OWNER |                   // 0x00080000
        READ_CONTROL |                  // 0x00020000
        ADS_RIGHT_DS_CREATE_CHILD |     // 0x00000001
        ADS_RIGHT_DS_DELETE_CHILD |     // 0x00000002
        ADS_RIGHT_DS_READ_PROP |        // 0x00000010
        ADS_RIGHT_DS_WRITE_PROP |       // 0x00000020
        ADS_RIGHT_DS_CONTROL_ACCESS;    // 0x00000100
    
    // GENERIC_WRITE (0x40000000) expands to:
    // READ_CONTROL | WRITE_PROP | SELF
    const ACCESS_MASK EXPANDED_GENERIC_WRITE = 0x00020028;
    const ACCESS_MASK GENERIC_WRITE_CORE_RIGHTS = 
        READ_CONTROL |              // 0x00020000
        ADS_RIGHT_DS_WRITE_PROP |   // 0x00000020
        ADS_RIGHT_DS_SELF;          // 0x00000008
    
    // GENERIC_READ (0x80000000) expands to:
    // READ_CONTROL | LIST_CHILDREN | READ_PROP | LIST_OBJECT
    const ACCESS_MASK EXPANDED_GENERIC_READ = 0x00020094;
    const ACCESS_MASK GENERIC_READ_CORE_RIGHTS = 
        READ_CONTROL |              // 0x00020000
        ADS_RIGHT_ACTRL_DS_LIST |   // 0x00000004
        ADS_RIGHT_DS_READ_PROP |    // 0x00000010
        ADS_RIGHT_DS_LIST_OBJECT;   // 0x00000080
    
    // GENERIC_EXECUTE (0x20000000) expands to:
    // READ_CONTROL | LIST_CHILDREN
    const ACCESS_MASK EXPANDED_GENERIC_EXECUTE = 0x00020004;
    const ACCESS_MASK GENERIC_EXECUTE_CORE_RIGHTS = 
        READ_CONTROL |              // 0x00020000
        ADS_RIGHT_ACTRL_DS_LIST;    // 0x00000004
    
    // Check which generic right we're looking for
    if (genericRight == GENERIC_ALL) {
        // Check exact matches
        if (aceMask == EXPANDED_GENERIC_ALL || aceMask == EXPANDED_GENERIC_ALL_ALT) {
            return TRUE;
        }
        // Check if mask contains all core rights
        if ((aceMask & GENERIC_ALL_CORE_RIGHTS) == GENERIC_ALL_CORE_RIGHTS) {
            return TRUE;
        }
    }
    else if (genericRight == GENERIC_WRITE) {
        // Check exact match
        if (aceMask == EXPANDED_GENERIC_WRITE) {
            return TRUE;
        }
        // Check if mask contains all core rights
        if ((aceMask & GENERIC_WRITE_CORE_RIGHTS) == GENERIC_WRITE_CORE_RIGHTS) {
            return TRUE;
        }
    }
    else if (genericRight == GENERIC_READ) {
        // Check exact match
        if (aceMask == EXPANDED_GENERIC_READ) {
            return TRUE;
        }
        // Check if mask contains all core rights
        if ((aceMask & GENERIC_READ_CORE_RIGHTS) == GENERIC_READ_CORE_RIGHTS) {
            return TRUE;
        }
    }
    else if (genericRight == GENERIC_EXECUTE) {
        // Check exact match
        if (aceMask == EXPANDED_GENERIC_EXECUTE) {
            return TRUE;
        }
        // Check if mask contains all core rights
        if ((aceMask & GENERIC_EXECUTE_CORE_RIGHTS) == GENERIC_EXECUTE_CORE_RIGHTS) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Helper function to check if an ACE matches a specific GUID for extended rights
BOOL DoesAceMatchGuid(PPARSED_ACE_INFO ace, const char* guidString) {
    if (!ace || !guidString) return FALSE;
    
    // Must be an object ACE with object type
    if (!ace->IsObjectAce || !ace->HasObjectType) {
        return FALSE;
    }
    
    // Parse the GUID string and compare
    GUID targetGuid;
    MSVCRT$memset(&targetGuid, 0, sizeof(GUID));
    if (StringToGuid(guidString, &targetGuid)) {
        return AreGuidsEqual(&ace->ObjectType, &targetGuid);
    }
    
    return FALSE;
}

// Helper function to check if an ACE matches our removal criteria
BOOL DoesAceMatch(PPARSED_ACE_INFO ace, const char* trusteeSid, ACCESS_MASK accessMask, 
                  BYTE aceType, GUID** guidsToMatch, DWORD guidCount) {
    if (!ace || !trusteeSid) return FALSE;
    
    // First check: SID must match
    if (!ace->TrusteeSid || MSVCRT$strcmp(ace->TrusteeSid, trusteeSid) != 0) {
        return FALSE;
    }
    
    // If we have GUIDs to match (like DCSync), check those
    if (guidsToMatch && guidCount > 0) {
        // Must be an object ACE with object type
        if (!ace->IsObjectAce || !ace->HasObjectType) {
            return FALSE;
        }
        
        // Check if ACE's GUID matches any of our target GUIDs
        for (DWORD i = 0; i < guidCount; i++) {
            if (guidsToMatch[i] && AreGuidsEqual(&ace->ObjectType, guidsToMatch[i])) {
                return TRUE;
            }
        }
        return FALSE;
    }
    
    // No GUID matching - check access mask and type
    // If access mask is 0, match any mask (remove all ACEs for this trustee)
    if (accessMask == 0) {
        // Check ACE type if specified
        if (aceType != 0xFF && ace->AceType != aceType) {
            return FALSE;
        }
        return TRUE;
    }
    
    // Check if the requested mask is a generic right that might be expanded
    // Handle GENERIC_ALL, GENERIC_WRITE, GENERIC_READ, GENERIC_EXECUTE
    if (accessMask == GENERIC_ALL || accessMask == GENERIC_WRITE || 
        accessMask == GENERIC_READ || accessMask == GENERIC_EXECUTE) {
        
        // Check if ACE mask is the expanded form of the generic right
        if (IsExpandedGenericRight(ace->Mask, accessMask)) {
            // ACE type check
            if (aceType != 0xFF && ace->AceType != aceType) {
                return FALSE;
            }
            return TRUE;
        }
        
        // Also check for literal generic right (rare but possible)
        if (ace->Mask == accessMask) {
            if (aceType != 0xFF && ace->AceType != aceType) {
                return FALSE;
            }
            return TRUE;
        }
        
        return FALSE;
    }
    
    // Normal access mask matching (not a generic right)
    if (ace->Mask != accessMask) {
        return FALSE;
    }
    
    // If aceType is 0xFF (wildcard), match any type
    if (aceType != 0xFF && ace->AceType != aceType) {
        return FALSE;
    }
    
    return TRUE;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments:
    // target_identifier, is_target_dn, trustee_identifier, is_trustee_dn,
    // access_mask (optional - can be keyword like "DCSync" or hex value),
    // ace_type (optional - 0xFF means any type),
    // ace_index (optional - -1 means use matching, >= 0 means remove specific index),
    // search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* trusteeIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTrusteeDN = BeaconDataInt(&parser);
    char* accessMaskStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* aceTypeStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    int aceIndex = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting RemoveACE operation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    
    // Check if this is a special keyword-based removal (e.g., DCSync)
    BOOL isDCSyncRemoval = IsDCSyncKeyword(accessMaskStr);
    GUID** guidsToMatch = NULL;
    DWORD guidCount = 0;
    GUID dcsyncGuid1, dcsyncGuid2;
    
    if (isDCSyncRemoval) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] DCSync removal detected");
        
        // Parse the two DCSync GUIDs
        MSVCRT$memset(&dcsyncGuid1, 0, sizeof(GUID));
        MSVCRT$memset(&dcsyncGuid2, 0, sizeof(GUID));
        
        if (StringToGuid(GUID_DS_REPLICATION_GET_CHANGES, &dcsyncGuid1) &&
            StringToGuid(GUID_DS_REPLICATION_GET_CHANGES_ALL, &dcsyncGuid2)) {
            
            guidsToMatch = (GUID**)MSVCRT$malloc(2 * sizeof(GUID*));
            if (guidsToMatch) {
                guidsToMatch[0] = &dcsyncGuid1;
                guidsToMatch[1] = &dcsyncGuid2;
                guidCount = 2;
            }
        }
    }
    
    // Determine removal mode
    BOOL removeByIndex = (aceIndex >= 0);
    ACCESS_MASK accessMask = 0;
    BYTE aceType = 0xFF; // Wildcard by default
    
    if (removeByIndex) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: Remove by ACE Index: %d", aceIndex);
    } else {
        // Remove by matching
        if (!trusteeIdentifier || MSVCRT$strlen(trusteeIdentifier) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Trustee identifier required when not removing by index");
            if (guidsToMatch) MSVCRT$free(guidsToMatch);
            return;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: Remove by matching trustee and permissions");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Trustee: %s %s", trusteeIdentifier, isTrusteeDN ? "(DN)" : "(name)");
        
        // Parse access mask and type (unless DCSync)
        if (!isDCSyncRemoval) {
            if (accessMaskStr && MSVCRT$strlen(accessMaskStr) > 0) {
                accessMask = ParseAccessMask(accessMaskStr);
                if (accessMask != 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Access Mask: %s (0x%08x)", accessMaskStr, accessMask);
                }
            }
            
            if (aceTypeStr && MSVCRT$strlen(aceTypeStr) > 0) {
                aceType = ParseAceType(aceTypeStr);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE Type: %s (0x%02x)", aceTypeStr, aceType);
            }
            
            if (accessMask == 0 && aceType == 0xFF) {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Will remove ALL ACEs for this trustee");
            }
        }
    }
    
    // Display optional parameters
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
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Initializing LDAP connection...");
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        if (guidsToMatch) MSVCRT$free(guidsToMatch);
        return;
    }
    
    // Get default naming context
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        if (guidsToMatch) MSVCRT$free(guidsToMatch);
        CleanupLDAP(ld);
        return;
    }
    
    // Variables for cleanup
    char* targetDN = NULL;
    char* trusteeDN = NULL;
    PSID pTrusteeSid = NULL;
    char* trusteeSidStr = NULL;
    BERVAL* sdBerval = NULL;
    PSD_INFO sdInfo = NULL;
    PSID pObjectSid = NULL;
    char* objectSidStr = NULL;
    DWORD* acesToRemove = NULL;
    PACL pNewDacl = NULL;
    BERVAL* newSdBerval = NULL;
    
    // Resolve target DN
    if (isDCSyncRemoval && !isTargetDN && MSVCRT$strlen(targetIdentifier) == 0) {
        // For DCSync, empty target means domain root
        size_t len = MSVCRT$strlen(defaultNC) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, defaultNC);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using domain root: %s", targetDN);
        }
    } else if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, targetIdentifier);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided DN: %s", targetDN);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", targetIdentifier);
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Resolved target DN: %s", targetDN);
    }
    
    if (!targetDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve target DN");
        goto cleanup;
    }
    
    // Resolve trustee if removing by match (not by index)
    if (!removeByIndex) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Resolving trustee...");
        
        if (isTrusteeDN) {
            size_t len = MSVCRT$strlen(trusteeIdentifier) + 1;
            trusteeDN = (char*)MSVCRT$malloc(len);
            if (trusteeDN) {
                MSVCRT$strcpy(trusteeDN, trusteeIdentifier);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided trustee DN: %s", trusteeDN);
            }
        } else {
            char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
            trusteeDN = FindObjectDN(ld, trusteeIdentifier, searchBase);
            if (!trusteeDN) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Trustee '%s' not found", trusteeIdentifier);
                goto cleanup;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Resolved trustee DN: %s", trusteeDN);
        }
        
        // Get trustee's SID
        pTrusteeSid = GetObjectSid(ld, trusteeDN);
        if (!pTrusteeSid) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get trustee's objectSid");
            goto cleanup;
        }
        
        trusteeSidStr = SidToString(pTrusteeSid);
        if (!trusteeSidStr) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert trustee SID to string");
            goto cleanup;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Trustee SID: %s", trusteeSidStr);
    }
    
    // Read current security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Reading security descriptor...");
    sdBerval = ReadSecurityDescriptor(ld, targetDN);
    if (!sdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read security descriptor");
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Read security descriptor (%d bytes)", sdBerval->bv_len);
    
    // Parse security descriptor
    sdInfo = ParseSecurityDescriptor((BYTE*)sdBerval->bv_val, sdBerval->bv_len);
    if (!sdInfo) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse security descriptor");
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Current DACL has %d ACE(s)", sdInfo->DaclAceCount);
    
    // Get target's SID for display
    pObjectSid = GetObjectSid(ld, targetDN);
    if (pObjectSid) {
        objectSidStr = SidToString(pObjectSid);
    }
    
    // Determine which ACEs to remove
    DWORD removeCount = 0;
    
    if (removeByIndex) {
        // Remove by specific index
        if (aceIndex >= (int)sdInfo->DaclAceCount) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ACE index %d out of range (max: %d)", 
                        aceIndex, sdInfo->DaclAceCount - 1);
            goto cleanup;
        }
        
        acesToRemove = (DWORD*)MSVCRT$malloc(sizeof(DWORD));
        if (!acesToRemove) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
            goto cleanup;
        }
        
        acesToRemove[0] = aceIndex;
        removeCount = 1;
        
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Will remove ACE at index %d:", aceIndex);
        PrintAceInfo(&sdInfo->DaclAces[aceIndex], aceIndex, targetDN, objectSidStr);
        
    } else {
        // Remove by matching - scan for all matching ACEs
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Scanning for matching ACEs...");
        
        // First pass: count matches
        for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
            if (DoesAceMatch(&sdInfo->DaclAces[i], trusteeSidStr, accessMask, aceType, 
                           guidsToMatch, guidCount)) {
                removeCount++;
            }
        }
        
        if (removeCount == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No matching ACEs found for this trustee");
            goto cleanup;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d matching ACE(s) to remove", removeCount);
        
        // Allocate array for indices
        acesToRemove = (DWORD*)MSVCRT$malloc(removeCount * sizeof(DWORD));
        if (!acesToRemove) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
            goto cleanup;
        }
        
        // Second pass: collect indices and display
        DWORD idx = 0;
        for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
            if (DoesAceMatch(&sdInfo->DaclAces[i], trusteeSidStr, accessMask, aceType,
                           guidsToMatch, guidCount)) {
                acesToRemove[idx++] = i;
                BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Will remove ACE #%d:", i);
                PrintAceInfo(&sdInfo->DaclAces[i], i, targetDN, objectSidStr);
            }
        }
    }
    
    // Get old DACL from security descriptor
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBerval->bv_val;
    PACL pOldDacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    
    if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, &daclDefaulted)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get DACL from security descriptor");
        goto cleanup;
    }
    
    // Create new DACL without the specified ACEs
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Creating new DACL...");
    pNewDacl = CreateNewDaclWithoutAces(pOldDacl, acesToRemove, removeCount);
    
    if (!pNewDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create new DACL");
        goto cleanup;
    }
    
    // Build new security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Building new security descriptor...");
    
    BYTE absoluteSDBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR pNewSD = (PSECURITY_DESCRIPTOR)absoluteSDBuffer;
    
    if (!ADVAPI32$InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize security descriptor");
        goto cleanup;
    }
    
    // Copy owner and group from original
    PSID pOwner = NULL;
    BOOL ownerDefaulted = FALSE;
    ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &ownerDefaulted);
    if (pOwner) {
        ADVAPI32$SetSecurityDescriptorOwner(pNewSD, pOwner, ownerDefaulted);
    }
    
    PSID pGroup = NULL;
    BOOL groupDefaulted = FALSE;
    ADVAPI32$GetSecurityDescriptorGroup(pSD, &pGroup, &groupDefaulted);
    if (pGroup) {
        ADVAPI32$SetSecurityDescriptorGroup(pNewSD, pGroup, groupDefaulted);
    }
    
    // Set the new DACL
    if (!ADVAPI32$SetSecurityDescriptorDacl(pNewSD, TRUE, pNewDacl, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set DACL");
        goto cleanup;
    }
    
    // Copy SACL if present
    PACL pSacl = NULL;
    BOOL saclPresent = FALSE;
    BOOL saclDefaulted = FALSE;
    if (ADVAPI32$GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted)) {
        if (saclPresent) {
            ADVAPI32$SetSecurityDescriptorSacl(pNewSD, TRUE, pSacl, saclDefaulted);
        }
    }
    
    // Convert to self-relative format for LDAP
    newSdBerval = ConvertSecurityDescriptorToBerval(pNewSD);
    if (!newSdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor");
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Security descriptor ready (%d bytes)", newSdBerval->bv_len);
    
    // Write back to LDAP
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Writing modified security descriptor...");
    BOOL writeSuccess = WriteSecurityDescriptor(ld, targetDN, newSdBerval);
    
    if (writeSuccess) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: ACE(s) removed successfully!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed: %d ACE(s)", removeCount);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] New DACL: %d ACE(s) (was %d)", 
                    sdInfo->DaclAceCount - removeCount, sdInfo->DaclAceCount);
        
        if (isDCSyncRemoval) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DCSync rights revoked");
        }
        
        // Verify
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Verifying changes...");
        BERVAL* verifyBerval = ReadSecurityDescriptor(ld, targetDN);
        if (verifyBerval) {
            PSD_INFO verifyInfo = ParseSecurityDescriptor((BYTE*)verifyBerval->bv_val, 
                                                          verifyBerval->bv_len);
            if (verifyInfo) {
                DWORD expectedCount = sdInfo->DaclAceCount - removeCount;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Verification: DACL has %d ACE(s) (expected %d)", 
                            verifyInfo->DaclAceCount, expectedCount);
                
                if (verifyInfo->DaclAceCount == expectedCount) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] ACE count matches - operation successful");
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Warning: ACE count mismatch");
                }
                
                FreeSecurityDescriptorInfo(verifyInfo);
            }
            MSVCRT$free(verifyBerval->bv_val);
            MSVCRT$free(verifyBerval);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to remove ACE(s)");
    }

cleanup:
    // Free all allocated resources
    if (newSdBerval) {
        if (newSdBerval->bv_val) MSVCRT$free(newSdBerval->bv_val);
        MSVCRT$free(newSdBerval);
    }
    if (pNewDacl) MSVCRT$free(pNewDacl);
    if (acesToRemove) MSVCRT$free(acesToRemove);
    if (objectSidStr) MSVCRT$free(objectSidStr);
    if (pObjectSid) MSVCRT$free(pObjectSid);
    if (sdInfo) FreeSecurityDescriptorInfo(sdInfo);
    if (sdBerval) {
        if (sdBerval->bv_val) MSVCRT$free(sdBerval->bv_val);
        MSVCRT$free(sdBerval);
    }
    if (trusteeSidStr) MSVCRT$free(trusteeSidStr);
    if (pTrusteeSid) MSVCRT$free(pTrusteeSid);
    if (trusteeDN) MSVCRT$free(trusteeDN);
    if (targetDN) MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (guidsToMatch) MSVCRT$free(guidsToMatch);
    CleanupLDAP(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Operation complete");
}