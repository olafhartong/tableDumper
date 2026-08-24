package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaskSensitiveCommandLineCredentialForms(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		row   map[string]any
	}{
		{
			name:  "long arguments and preserved quotes",
			input: `tool --username alice --password "s e c" --api-key=abc --app-id 123 --client-secret 'top secret'`,
			want:  `tool --username *** --password "***" --api-key=*** --app-id *** --client-secret '***'`,
		},
		{
			name:  "PowerShell-style arguments",
			input: `tool -Username bob -Password p@ss -ClientId app-guid -ClientSecret secret`,
			want:  `tool -Username *** -Password *** -ClientId *** -ClientSecret ***`,
		},
		{
			name:  "short arguments and authentication headers",
			input: `curl -u user:pass -p password -H "Authorization: Bearer token123" -H "x-api-key: key123"`,
			want:  `curl -u *** -p *** -H "Authorization: Bearer ***" -H "x-api-key: ***"`,
		},
		{
			name:  "short assigned arguments and cloud environment variables",
			input: `tool -u=alice -p:'secret' AZURE_CLIENT_ID=app-guid ARM_CLIENT_SECRET=secret AWS_SECRET_ACCESS_KEY=aws-secret`,
			want:  `tool -u=*** -p:'***' AZURE_CLIENT_ID=*** ARM_CLIENT_SECRET=*** AWS_SECRET_ACCESS_KEY=***`,
		},
		{
			name:  "escaped JSON properties",
			input: `tool --properties "{\"clientSecret\":\"secret\",\"username\":\"alice\"}"`,
			want:  `tool --properties "{\"clientSecret\":\"***\",\"username\":\"***\"}"`,
		},
		{
			name:  "authorization assignment",
			input: `tool Authorization="Bearer token123"`,
			want:  `tool Authorization="Bearer ***"`,
		},
		{
			name:  "connection string",
			input: `Server=db;User Id=alice;Password=pwd;Client Id=appid;Client Secret=secret;Database=logs`,
			want:  `Server=db;User Id=***;Password=***;Client Id=***;Client Secret=***;Database=logs`,
		},
		{
			name:  "URL credentials and query secrets",
			input: `tool https://alice:secret@example.test/path?api_key=abc&sig=xyz&mode=read`,
			want:  `tool https://***@example.test/path?api_key=***&sig=***&mode=read`,
		},
		{
			name:  "known event identities in paths and account forms",
			input: `runas CONTOSO\layla felix@example.test C:\Users\layla\tool.exe /mode safe`,
			want:  `runas CONTOSO\*** *** C:\Users\***\tool.exe /mode safe`,
			row: map[string]any{
				"AccountName": "layla",
				"AccountUpn":  "felix@example.test",
			},
		},
		{
			name:  "recognizable standalone tokens",
			input: `tool eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature AKIAIOSFODNN7EXAMPLE`,
			want:  `tool *** ***`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.row == nil {
				test.row = map[string]any{}
			}
			if got := maskSensitiveCommandLine(test.input, test.row); got != test.want {
				t.Fatalf("maskSensitiveCommandLine() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPseudonymizeRowsAlwaysMasksSensitiveCommandLineValues(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}

	rows := []map[string]any{{
		"AccountName":                  "alice",
		"FileName":                     "tool.exe",
		"ProcessCommandLine":           `tool.exe --username alice --password "secret value" --api-key key-123`,
		"InitiatingProcessFileName":    "launcher.exe",
		"InitiatingProcessCommandLine": `launcher.exe --app-id app-123 --app-secret secret-456`,
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if got := converted[0]["ProcessCommandLine"].(string); got != `tool.exe --username *** --password "***" --api-key ***` {
		t.Fatalf("ProcessCommandLine = %q", got)
	}
	if got := converted[0]["InitiatingProcessCommandLine"].(string); got != `launcher.exe --app-id *** --app-secret ***` {
		t.Fatalf("InitiatingProcessCommandLine = %q", got)
	}
	for _, field := range []string{"ProcessCommandLine", "InitiatingProcessCommandLine"} {
		value := converted[0][field].(string)
		for _, secret := range []string{"alice", "secret value", "key-123", "app-123", "secret-456"} {
			if strings.Contains(value, secret) {
				t.Fatalf("%s still contains sensitive value %q: %q", field, secret, value)
			}
		}
	}
}

func TestCommandLineMaskingComposesWithOptionalFilenameLinking(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	pseudonyms.ConfigureFilenamePseudonymization(true)

	rows := []map[string]any{{
		"FileName":           "tool.exe",
		"FolderPath":         `C:\Tools\tool.exe`,
		"ProcessCommandLine": `tool.exe --username alice --password secret`,
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	filename := converted[0]["FileName"].(string)
	if got, want := converted[0]["ProcessCommandLine"].(string), filename+" --username *** --password ***"; got != want {
		t.Fatalf("ProcessCommandLine = %q, want %q", got, want)
	}
}
