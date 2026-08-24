package app

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
)

const (
	identityPseudonymFields = "*accountname,*username,*userprincipalname,*userprincipal,*upn,*email,*emailaddress,*mailaddress,*mailaddresses"
	emailPseudonymFields    = "*userprincipalname,*userprincipal,*upn,*email,*emailaddress,*mailaddress,*mailaddresses,senderfromaddress,sendermailfromaddress"
	filePseudonymFields     = "*filename,*fileinternalname,*fileoriginalname,*folderpath,*filepath,*fullpath,*filedirectory,*workingdirectory,*currentdirectory,*homedirectory,*profilepath,*sharename"
	domainPseudonymFields   = "*domain,*domainname,*accountdomain,*dnsname,*dnsdomain,*urldomain,*fqdn"
	computerPseudonymFields = "computer,*devicename,*computername,*machinename,*hostname,*workstationname,*instancevmname"
	azurePseudonymFields    = "*subscriptionid,*resourcegroupname,*resourcegroup,*resourceid"
	defaultPseudonymFields  = identityPseudonymFields + "," + filePseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields
)

var defaultPseudonymFieldsByTable = map[string]string{
	"deviceprocessevents":     defaultPseudonymFields,
	"devicefileevents":        defaultPseudonymFields,
	"deviceevents":            defaultPseudonymFields,
	"deviceimageloadevents":   defaultPseudonymFields,
	"devicenetworkevents":     defaultPseudonymFields,
	"deviceregistryevents":    defaultPseudonymFields,
	"devicelogonevents":       defaultPseudonymFields,
	"deviceinfo":              domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"devicenetworkinfo":       domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"identitylogonevents":     identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"identityqueryevents":     identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"identitydirectoryevents": identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"alertevidence":           defaultPseudonymFields,
	"behaviorentities":        defaultPseudonymFields,
	"cloudappevents":          defaultPseudonymFields,
	"aadspndata":              identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"aadsignineventsbeta":     identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"azureactivity":           identityPseudonymFields + "," + domainPseudonymFields + "," + computerPseudonymFields + "," + azurePseudonymFields,
	"emailattachmentinfo":     emailPseudonymFields + "," + filePseudonymFields + "," + domainPseudonymFields,
	"emailevents":             emailPseudonymFields + "," + domainPseudonymFields,
	"emailpostdeliveryevents": emailPseudonymFields + "," + domainPseudonymFields,
	"emailurlinfo":            domainPseudonymFields,
	"urlclickevents":          emailPseudonymFields + "," + domainPseudonymFields,
}

// Some schema columns have generic names whose meaning is only clear from the
// table description. Keep them table-scoped so a column called Name, User,
// Host, or Resource is not pseudonymized everywhere.
var additionalPseudonymFieldsByTable = map[string]string{
	"aadnoninteractiveusersigninlogs":       "alternatesigninname",
	"abapauditlog":                          "user,host",
	"abapchangedocslog":                     "user",
	"abaptabledatalog":                      "user,host",
	"abapuserdetails":                       "user",
	"alert":                                 "lastmodifiedby,resolvedby",
	"alertevidence":                         "remoteurl",
	"asimalerteventlogs":                    "user,processname",
	"asimassetentitylogs":                   "user",
	"asimfileeventlogs":                     "actingprocessname",
	"asimprocesseventlogs":                  "actingprocessname,parentprocessname,targetprocessname",
	"asimregistryeventlogs":                 "actingprocessname,parentprocessname",
	"awsekslogs":                            "user",
	"awscloudtrail":                         "clientprovidedhostheader",
	"awsroute53resolver":                    "queryname",
	"azureactivity":                         "resource",
	"azurediagnostics":                      "resource",
	"azuremetrics":                          "resource",
	"behavioranalytics":                     "actorname,actorprincipalname,device",
	"behaviorentities":                      "remoteurl",
	"cloudprocessevents":                    "parentprocessname,processname",
	"communicationcomplianceactivity":       "actorname",
	"copilotactivity":                       "actorname",
	"crowdstrikealerts":                     "assignedtoname",
	"crowdstrikedetections":                 "assignedtoname",
	"crowdstrikehosts":                      "lastloginuser",
	"crowdstrikeincidents":                  "assignedtoname",
	"deviceevents":                          "remoteurl",
	"devicenetworkevents":                   "remoteurl",
	"dnsauditevents":                        "name,zonefile",
	"dynamics365activity":                   "userid",
	"entraidsigninevents":                   "alternatesigninname",
	"gcpdns":                                "queryname",
	"graphnotificationsactivitylogs":        "subscriptionidentity",
	"heartbeat":                             "resource",
	"ilumioinsights":                        "resourcesubid",
	"linuxauditlog":                         "user",
	"microsoftpurviewinformationprotection": "userid",
	"officeactivity":                        "userid",
	"powerappsactivity":                     "actorname",
	"powerautomateactivity":                 "actorname",
	"powerbiactivity":                       "actorname",
	"powerplatformadminactivity":            "actorname",
	"powerplatformconnectoractivity":        "actorname",
	"powerplatformdlpactivity":              "actorname",
	"projectactivity":                       "actorname,onbehalfofresid",
	"salesforceaudittrail":                  "createdbyname",
	"securityevent":                         "account,callerprocessname,clientname,newprocessname,parentprocessname,processname,targetaccount,workstation,userworkstations",
	"sentinelalibabacloudwaflogs":           "host,matchedhost",
	"sentinelbehaviorentities":              "remoteurl",
	"signinlogs":                            "alternatesigninname",
}

func defaultPseudonymFieldsForTable(table string) string {
	name := strings.ToLower(strings.TrimSpace(table))
	fields, ok := defaultPseudonymFieldsByTable[name]
	if !ok {
		fields = defaultPseudonymFields
	}
	if additional := additionalPseudonymFieldsByTable[name]; additional != "" {
		return fields + "," + additional
	}
	return fields
}

type pseudonymFieldPolicy struct {
	patterns []string
}

func newPseudonymFieldPolicy(value string) (*pseudonymFieldPolicy, error) {
	parts := strings.Split(value, ",")
	patterns := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		pattern, err := normalizePseudonymFieldPattern(part)
		if err != nil {
			return nil, err
		}
		if pattern == "" {
			return nil, errors.New("[!] pseudonym field patterns must not be empty")
		}
		if _, err := path.Match(pattern, "fieldname"); err != nil {
			return nil, fmt.Errorf("[!] invalid pseudonym field pattern %q: %w", part, err)
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		patterns = append(patterns, pattern)
	}
	if len(patterns) == 0 {
		return nil, errors.New("[!] at least one pseudonym field pattern is required")
	}
	return &pseudonymFieldPolicy{patterns: patterns}, nil
}

func normalizePseudonymFieldPattern(value string) (string, error) {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '*' || r == '?':
			builder.WriteRune(r)
		case unicode.IsSpace(r) || r == '_' || r == '-' || r == '.':
			continue
		default:
			return "", fmt.Errorf("[!] pseudonym field pattern %q contains unsupported character %q", value, r)
		}
	}
	return builder.String(), nil
}

func (p *pseudonymFieldPolicy) Matches(field string) bool {
	if p == nil {
		return false
	}
	names := []string{normalizeFieldName(field)}
	if rawName := normalizeRawFieldName(field); rawName != "" && rawName != names[0] {
		names = append(names, rawName)
	}
	if names[0] == "" {
		return false
	}
	for _, pattern := range p.patterns {
		for _, name := range names {
			matched, err := path.Match(pattern, name)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}
