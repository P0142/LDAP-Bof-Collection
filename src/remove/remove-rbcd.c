#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

// Helper function to check if an ACE matches our criteria
BOOL DoesRbcdAceMatch(PPARSED_ACE_INFO ace, const char* trusteeSid, ACCESS_MASK accessMask) {
    if (!ace || !trusteeSid) return FALSE;
    
    // Check SID match
    if (ace->TrusteeSid && MSVCRT$strcmp(ace->TrusteeSid, trusteeSid) == 0) {
        // If access mask is 0, match any mask (remove all ACEs for this trustee)
        if (accessMask == 0) {
            return TRUE;
        }
        
        // Check if access mask matches
        if (ace->Mask == accessMask) {
            return TRUE;
        }
    }
    
    return FALSE;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments:
    // target_identifier, is_target_dn, principal_identifier (optional), is_principal_dn,
    // access_mask (optional - 0 means remove all for principal),
    // clear_all (if true, remove entire RBCD attribute),
    // search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* principalIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isPrincipalDN = BeaconDataInt(&parser);
    char* accessMaskStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    int clearAll = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting RemoveRBCD operation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    
    // Determine removal mode
    BOOL removeAllRbcd = clearAll;
    BOOL removeByPrincipal = FALSE;
    char* principalSidStr = NULL;
    PSID pPrincipalSid = NULL;
    ACCESS_MASK accessMask = 0;
    
    if (removeAllRbcd) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: Clear all RBCD configuration");
    } else {
        if (!principalIdentifier || MSVCRT$strlen(principalIdentifier) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Principal identifier required when not using --clear-all");
            return;
        }
        
        removeByPrincipal = TRUE;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: Remove by principal");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Principal: %s %s", principalIdentifier, isPrincipalDN ? "(DN)" : "(name)");
        
        // Parse access mask if provided
        if (accessMaskStr && MSVCRT$strlen(accessMaskStr) > 0) {
            accessMask = ParseAccessMask(accessMaskStr);
            if (accessMask != 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Access Mask Filter: %s (0x%08x)", accessMaskStr, accessMask);
            }
        }
        
        if (accessMask == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: Remove ALL ACEs for principal (no mask filter)");
        }
    }
    
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
        return;
    }
    
    // Get default naming context
    char* defaultNC = NULL;
    char* targetDN = NULL;
    char* principalDN = NULL;
    
    
    defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }
    
    // Resolve target DN
    if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, targetIdentifier);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided target DN: %s", targetDN);
    } else {
        
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve target DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Target '%s' not found", targetIdentifier);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Resolved target DN: %s", targetDN);
    }
    
    // Resolve principal if removing by principal
    if (removeByPrincipal) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Resolving principal information...");
        
        if (isPrincipalDN) {
            size_t len = MSVCRT$strlen(principalIdentifier) + 1;
            principalDN = (char*)MSVCRT$malloc(len);
            if (principalDN) {
                MSVCRT$strcpy(principalDN, principalIdentifier);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided principal DN: %s", principalDN);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Resolving principal DN...");
            char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
            principalDN = FindObjectDN(ld, principalIdentifier, searchBase);
            
            if (!principalDN) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve principal DN");
                BeaconPrintf(CALLBACK_ERROR, "[!] Principal '%s' not found", principalIdentifier);
                if (targetDN) MSVCRT$free(targetDN);
                MSVCRT$free(defaultNC);
                if (dcHostname) MSVCRT$free(dcHostname);
                CleanupLDAP(ld);
                return;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Resolved principal DN: %s", principalDN);
        }
        
        // Get principal's objectSid
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Retrieving principal's objectSid...");
        pPrincipalSid = GetObjectSid(ld, principalDN);
        
        if (!pPrincipalSid) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve principal's objectSid");
            if (principalDN) MSVCRT$free(principalDN);
            if (targetDN) MSVCRT$free(targetDN);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        
        // Convert SID to string for matching
        principalSidStr = SidToString(pPrincipalSid);
        if (principalSidStr) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Principal SID: %s", principalSidStr);
        }
    }
    
    // Read current RBCD configuration
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Reading current RBCD configuration...");
    
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char* attrs[] = { "msDS-AllowedToActOnBehalfOfOtherIdentity", NULL };
    struct berval** values = NULL;
    BERVAL* currentRbcdBerval = NULL;

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
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for object");
        PrintLdapError("Search for RBCD attribute", result);
        goto cleanup;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object not found");
        WLDAP32$ldap_msgfree(searchResult);
        goto cleanup;
    }

    // Get current RBCD configuration
    values = WLDAP32$ldap_get_values_len(ld, entry, "msDS-AllowedToActOnBehalfOfOtherIdentity");
    
    if (!values || !values[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No RBCD configuration found on target");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Nothing to remove");
        WLDAP32$ldap_msgfree(searchResult);
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found existing RBCD configuration (%d bytes)", values[0]->bv_len);
    
    // Allocate and copy
    currentRbcdBerval = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (currentRbcdBerval) {
        currentRbcdBerval->bv_len = values[0]->bv_len;
        currentRbcdBerval->bv_val = (char*)MSVCRT$malloc(currentRbcdBerval->bv_len);
        if (currentRbcdBerval->bv_val) {
            MSVCRT$memcpy(currentRbcdBerval->bv_val, values[0]->bv_val, currentRbcdBerval->bv_len);
        }
    }
    
    WLDAP32$ldap_value_free_len(values);
    WLDAP32$ldap_msgfree(searchResult);
    
    // If clearing all, just delete the attribute
    if (removeAllRbcd) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Clearing all RBCD configuration...");
        
        LDAPModA rbcdMod;
        rbcdMod.mod_op = LDAP_MOD_DELETE;
        rbcdMod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
        rbcdMod.mod_vals.modv_strvals = NULL;
        
        LDAPModA* mods[] = { &rbcdMod, NULL };
        
        result = WLDAP32$ldap_modify_s(ld, targetDN, mods);
        
        if (result == LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: All RBCD configuration removed!");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] The msDS-AllowedToActOnBehalfOfOtherIdentity attribute has been deleted");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to remove RBCD configuration");
            PrintLdapError("Delete RBCD attribute", result);
        }
        
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Parse the security descriptor to get current DACL
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing current RBCD security descriptor...");
    PSD_INFO sdInfo = ParseSecurityDescriptor((BYTE*)currentRbcdBerval->bv_val, currentRbcdBerval->bv_len);
    
    if (!sdInfo) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse security descriptor");
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Current RBCD DACL has %d ACE(s)", sdInfo->DaclAceCount);
    
    // Find ACEs to remove
    DWORD* acesToRemove = NULL;
    DWORD removeCount = 0;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for matching ACEs...");
    
    // First pass: count matches
    for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
        if (DoesRbcdAceMatch(&sdInfo->DaclAces[i], principalSidStr, accessMask)) {
            removeCount++;
        }
    }
    
    if (removeCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No matching ACEs found, Principal may not have RBCD configured on this target");
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d matching ACE(s) to remove", removeCount);
    
    // Allocate array for indices
    acesToRemove = (DWORD*)MSVCRT$malloc(removeCount * sizeof(DWORD));
    if (!acesToRemove) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Second pass: collect indices
    DWORD idx = 0;
    for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
        if (DoesRbcdAceMatch(&sdInfo->DaclAces[i], principalSidStr, accessMask)) {
            acesToRemove[idx++] = i;
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Will remove ACE at index %d:", i);
            if (sdInfo->DaclAces[i].TrusteeSid) {
                BeaconPrintf(CALLBACK_OUTPUT, "    SID: %s", sdInfo->DaclAces[i].TrusteeSid);
            }
            char* maskStr = GetAccessMaskString(sdInfo->DaclAces[i].Mask);
            BeaconPrintf(CALLBACK_OUTPUT, "    Access: %s (0x%08x)", maskStr, sdInfo->DaclAces[i].Mask);
        }
    }
    
    // Get old DACL from security descriptor
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)currentRbcdBerval->bv_val;
    PACL pOldDacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    
    if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, &daclDefaulted)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get DACL from security descriptor");
        MSVCRT$free(acesToRemove);
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Check if we're removing all ACEs
    if (removeCount == sdInfo->DaclAceCount) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Removing all ACEs would leave RBCD empty");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Deleting entire RBCD attribute instead");
        
        LDAPModA rbcdMod;
        rbcdMod.mod_op = LDAP_MOD_DELETE;
        rbcdMod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
        rbcdMod.mod_vals.modv_strvals = NULL;
        
        LDAPModA* mods[] = { &rbcdMod, NULL };
        
        result = WLDAP32$ldap_modify_s(ld, targetDN, mods);
        
        if (result == LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: All RBCD configuration removed!");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed principal: %s", principalIdentifier);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to remove RBCD configuration");
            PrintLdapError("Delete RBCD attribute", result);
        }
        
        MSVCRT$free(acesToRemove);
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Create new DACL without the specified ACEs
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Creating new RBCD DACL without removed ACE(s)...");
    PACL pNewDacl = CreateNewDaclWithoutAces(pOldDacl, acesToRemove, removeCount);
    
    MSVCRT$free(acesToRemove);
    
    if (!pNewDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create new DACL");
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created new RBCD DACL");
    
    // Create new security descriptor with the new DACL
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Building new RBCD security descriptor...");
    
    BYTE absoluteSDBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR pNewSD = (PSECURITY_DESCRIPTOR)absoluteSDBuffer;
    
    if (!ADVAPI32$InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize new security descriptor");
        MSVCRT$free(pNewDacl);
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Copy owner and group from old SD
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
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set new DACL in security descriptor");
        MSVCRT$free(pNewDacl);
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] New RBCD security descriptor built successfully");
    
    // Convert to self-relative format
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Converting to self-relative format...");
    BERVAL* newRbcdBerval = ConvertSecurityDescriptorToBerval(pNewSD);
    
    if (!newRbcdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to BERVAL");
        MSVCRT$free(pNewDacl);
        FreeSecurityDescriptorInfo(sdInfo);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Converted to self-relative format (%d bytes)", newRbcdBerval->bv_len);
    
    // Write back to LDAP
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Writing modified RBCD configuration to LDAP...");
    
    struct berval* modValues[] = { newRbcdBerval, NULL };
    LDAPModA rbcdMod;
    rbcdMod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    rbcdMod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    rbcdMod.mod_vals.modv_bvals = modValues;
    
    LDAPModA* mods[] = { &rbcdMod, NULL };
    
    result = WLDAP32$ldap_modify_s(ld, targetDN, mods);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: RBCD principal(s) removed successfully!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed: %d ACE(s)", removeCount);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Remaining: %d ACE(s) (was %d)", 
                    sdInfo->DaclAceCount - removeCount, sdInfo->DaclAceCount);
        
        // Verify
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Verifying changes...");
        
        LDAPMessage* verifyResult = NULL;
        result = WLDAP32$ldap_search_s(ld, targetDN, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &verifyResult);
        
        if (result == LDAP_SUCCESS) {
            LDAPMessage* verifyEntry = WLDAP32$ldap_first_entry(ld, verifyResult);
            if (verifyEntry) {
                struct berval** verifyValues = WLDAP32$ldap_get_values_len(ld, verifyEntry, "msDS-AllowedToActOnBehalfOfOtherIdentity");
                if (verifyValues && verifyValues[0]) {
                    PSD_INFO verifyInfo = ParseSecurityDescriptor((BYTE*)verifyValues[0]->bv_val, verifyValues[0]->bv_len);
                    if (verifyInfo) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Verification: RBCD DACL now has %d ACE(s)", verifyInfo->DaclAceCount);
                        
                        DWORD expectedCount = sdInfo->DaclAceCount - removeCount;
                        if (verifyInfo->DaclAceCount == expectedCount) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] ACE count matches expected value");
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "[!] Warning: ACE count mismatch (expected %d, got %d)", 
                                        expectedCount, verifyInfo->DaclAceCount);
                        }
                        
                        FreeSecurityDescriptorInfo(verifyInfo);
                    }
                    WLDAP32$ldap_value_free_len(verifyValues);
                }
            }
            WLDAP32$ldap_msgfree(verifyResult);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to remove RBCD principal(s)");
        PrintLdapError("Modify RBCD attribute", result);
    }
    
    // Cleanup
    MSVCRT$free(pNewDacl);
    MSVCRT$free(newRbcdBerval->bv_val);
    MSVCRT$free(newRbcdBerval);
    FreeSecurityDescriptorInfo(sdInfo);
    if (currentRbcdBerval) {
        if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
        MSVCRT$free(currentRbcdBerval);
    }

cleanup:
    if (principalSidStr) MSVCRT$free(principalSidStr);
    if (pPrincipalSid) MSVCRT$free(pPrincipalSid);
    if (principalDN) MSVCRT$free(principalDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (targetDN) MSVCRT$free(targetDN);
    CleanupLDAP(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Operation complete");
}