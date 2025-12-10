#include <windows.h>
#include "../../_include/beacon.h"
#include "../common/ldap_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    
    // Parse arguments: computername_or_dn, password, ou_path, dc_address, disabled, use_ldaps
    char* computerIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isComputerDN = BeaconDataInt(&parser);
    char* password = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* ouPath = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int disabled = BeaconDataInt(&parser);
    int useLdaps = BeaconDataInt(&parser);
    
    if (!computerIdentifier || MSVCRT$strlen(computerIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Computer name or DN is required");
        return;
    }
    
    // Force LDAPS if password is provided
    BOOL requireLdaps = (password && MSVCRT$strlen(password) > 0) || useLdaps;
    
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
    
    // Extract domain name from defaultNC for SPNs and dnsHostName
    char domainName[256] = {0};
    char* dcPtr = defaultNC;
    int domainPos = 0;
    int firstDC = 1;
    
    while (*dcPtr && domainPos < 255) {
        if (dcPtr[0] == 'D' && dcPtr[1] == 'C' && dcPtr[2] == '=') {
            dcPtr += 3;
            if (!firstDC) domainName[domainPos++] = '.';
            firstDC = 0;
            while (*dcPtr && *dcPtr != ',' && domainPos < 255) {
                char ch = *dcPtr;
                if (ch >= 'A' && ch <= 'Z') ch += 32; // lowercase
                domainName[domainPos++] = ch;
                dcPtr++;
            }
        } else {
            dcPtr++;
        }
    }
    domainName[domainPos] = '\0';
    
    // Build computer DN and extract computername
    char computerDN[512];
    char computername[256];
    
    if (isComputerDN) {
        // Use provided DN directly
        MSVCRT$_snprintf(computerDN, sizeof(computerDN), "%s", computerIdentifier);
        
        // Extract CN from DN for sAMAccountName
        char* cnStart = MSVCRT$strstr(computerIdentifier, "CN=");
        if (cnStart) {
            cnStart += 3; // Skip "CN="
            char* cnEnd = MSVCRT$strstr(cnStart, ",");
            if (cnEnd) {
                int cnLen = cnEnd - cnStart;
                if (cnLen > 0 && cnLen < 256) {
                    MSVCRT$memcpy(computername, cnStart, cnLen);
                    computername[cnLen] = '\0';
                } else {
                    MSVCRT$strcpy(computername, cnStart);
                }
            } else {
                MSVCRT$strcpy(computername, cnStart);
            }
        } else {
            // Fallback: use the entire identifier as computername
            MSVCRT$strcpy(computername, computerIdentifier);
        }
    } else {
        // Build DN using provided OU path or default Computers container
        MSVCRT$strcpy(computername, computerIdentifier);
        
        if (ouPath && MSVCRT$strlen(ouPath) > 0) {
            // Use provided OU path
            MSVCRT$_snprintf(computerDN, sizeof(computerDN), "CN=%s,%s", computername, ouPath);
        } else {
            // Use default Computers container
            MSVCRT$_snprintf(computerDN, sizeof(computerDN), "CN=%s,CN=Computers,%s", computername, defaultNC);
        }
    }
    
    // Build sAMAccountName (with $)
    char samAccountName[256];
    MSVCRT$_snprintf(samAccountName, sizeof(samAccountName), "%s$", computername);
    
    // Build dnsHostName
    char dnsHostName[512];
    MSVCRT$_snprintf(dnsHostName, sizeof(dnsHostName), "%s.%s", computername, domainName);
    
    // Build default SPNs
    char spn1[256], spn2[256], spn3[256], spn4[256];
    MSVCRT$_snprintf(spn1, sizeof(spn1), "HOST/%s", computername);
    MSVCRT$_snprintf(spn2, sizeof(spn2), "HOST/%s.%s", computername, domainName);
    MSVCRT$_snprintf(spn3, sizeof(spn3), "RestrictedKrbHost/%s", computername);
    MSVCRT$_snprintf(spn4, sizeof(spn4), "RestrictedKrbHost/%s.%s", computername, domainName);
    
    // Prepare attributes
    char* objectClass_values[] = { "top", "person", "organizationalPerson", "user", "computer", NULL };
    LDAPModA objectClass_mod = { LDAP_MOD_ADD, "objectClass", { .modv_strvals = objectClass_values } };
    
    char* sam_values[] = { samAccountName, NULL };
    LDAPModA sam_mod = { LDAP_MOD_ADD, "sAMAccountName", { .modv_strvals = sam_values } };
    
    char* dnsHostName_values[] = { dnsHostName, NULL };
    LDAPModA dnsHostName_mod = { LDAP_MOD_ADD, "dNSHostName", { .modv_strvals = dnsHostName_values } };
    
    char* spn_values[] = { spn1, spn2, spn3, spn4, NULL };
    LDAPModA spn_mod = { LDAP_MOD_ADD, "servicePrincipalName", { .modv_strvals = spn_values } };
    
    // userAccountControl: 4096 = WORKSTATION_TRUST_ACCOUNT (enabled)
    //                     4098 = WORKSTATION_TRUST_ACCOUNT | ACCOUNTDISABLE (disabled)
    char* uac_values[] = { disabled ? "4098" : "4096", NULL };
    LDAPModA uac_mod = { LDAP_MOD_ADD, "userAccountControl", { .modv_strvals = uac_values } };
    
    // Password attribute (if provided)
    LDAPModA password_mod;
    BERVAL* encodedPassword = NULL;
    BERVAL* password_bervals[2] = { NULL, NULL };
    
    if (password && MSVCRT$strlen(password) > 0) {
        encodedPassword = EncodePassword(password);
        if (encodedPassword) {
            password_bervals[0] = encodedPassword;
            password_mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
            password_mod.mod_type = "unicodePwd";
            password_mod.mod_vals.modv_bvals = password_bervals;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to encode password, continuing without password");
        }
    }
    
    // Array of attribute modifications
    LDAPModA* attrs[9];
    int attrCount = 0;
    attrs[attrCount++] = &objectClass_mod;
    attrs[attrCount++] = &sam_mod;
    attrs[attrCount++] = &dnsHostName_mod;
    attrs[attrCount++] = &spn_mod;
    attrs[attrCount++] = &uac_mod;
    if (encodedPassword) {
        attrs[attrCount++] = &password_mod;
    }
    attrs[attrCount] = NULL;
    
    // Add computer
    ULONG result = WLDAP32$ldap_add_s(ld, computerDN, attrs);
    
    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created computer '%s'", computername);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s", computerDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] sAMAccountName: %s", samAccountName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] dnsHostName: %s", dnsHostName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] SPNs: HOST/%s, HOST/%s, RestrictedKrbHost/%s, RestrictedKrbHost/%s", 
                     computername, dnsHostName, computername, dnsHostName);
        if (encodedPassword) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Password: Set successfully");
        }
        if (disabled) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Account Status: DISABLED");
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create computer");
        PrintLdapError("Add computer", result);
        if (result == LDAP_ALREADY_EXISTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Computer already exists");
        } else if (result == LDAP_INSUFFICIENT_RIGHTS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Insufficient permissions");
        } else if (result == LDAP_INVALID_DN_SYNTAX) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax");
        } else if (result == LDAP_NO_SUCH_OBJECT) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Target OU does not exist");
        }
    }
    
    // Cleanup
    if (encodedPassword) {
        MSVCRT$free(encodedPassword->bv_val);
        MSVCRT$free(encodedPassword);
    }
    MSVCRT$free(defaultNC);
    MSVCRT$free(dcHostname);
    CleanupLDAP(ld);
}