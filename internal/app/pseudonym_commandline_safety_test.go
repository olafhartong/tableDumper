package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandSecretTokenBoundaries(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"attached mysql", `mysql -uroot -prootSecret -P3306 --database logs`, `mysql -u*** -p*** -P3306 --database logs`},
		{"attached mysql quoted", `mysql -p"root Secret" -h localhost`, `mysql -p"***" -h localhost`},
		{"attached curl", `curl -uuser:secret -Uproxy:secret --url https://example.test`, `curl -u*** -U*** --url https://example.test`},
		{"quoted connection", `tool "Password=quotedSecret;Server=db" --verbose`, `tool "Password=***;Server=db" --verbose`},
		{"single quoted connection", `tool 'User Id=alice;Password=quotedSecret;Server=db'`, `tool 'User Id=***;Password=***;Server=db'`},
		{"escaped double quote", `cmd /c tool --password "prefix\"tailSecret" --mode safe`, `cmd /c tool --password "***" --mode safe`},
		{"doubled single quote", `tool --password 'prefix''tailSecret' --mode safe`, `tool --password '***' --mode safe`},
		{"doubled double quote", `tool --password "prefix""tailSecret" --mode safe`, `tool --password "***" --mode safe`},
		{"unquoted escape", `tool --password prefix\ tailSecret --mode safe`, `tool --password *** --mode safe`},
		{"concatenated fragments", `tool --password prefix" secret "tailSecret --mode safe`, `tool --password *** --mode safe`},
		{"json escaped value", `tool --properties "{\"clientSecret\":\"prefix\\\"tailSecret\",\"mode\":\"safe\"}"`, `tool --properties "{\"clientSecret\":\"***\",\"mode\":\"safe\"}"`},
		{"json quoted value", `tool '{"password":"prefix\"tailSecret","mode":"safe"}'`, `tool '{"password":"***","mode":"safe"}'`},
		{"header escape", `curl -H "Authorization: Bearer prefix\"tailSecret" --verbose`, `curl -H "Authorization: Bearer ***" --verbose`},
		{"api header escape", `curl -H "x-api-key: prefix\"tailSecret" --verbose`, `curl -H "x-api-key: ***" --verbose`},
		{"unterminated", `tool --password "prefix\"tailSecret`, `tool --password ***`},
		{"ordinary options", `tool -port 443 -path /tmp -useragent browser --mode safe`, `tool -port 443 -path /tmp -useragent browser --mode safe`},
		{"quoted ordinary text", `tool "mode=normal;Server=db" --description 'safe message'`, `tool "mode=normal;Server=db" --description 'safe message'`},
	}
	tests = append(tests, struct{ name, input, want string }{"powershell escape", "tool -Password \"prefix`\"tailSecret\" -Mode safe", `tool -Password "***" -Mode safe`})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskSensitiveCommandLine(tc.input, nil)
			if got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
			if again := maskSensitiveCommandLine(got, nil); again != got {
				t.Fatalf("masking is not idempotent: %q", again)
			}
		})
	}
}

func TestEscapedAndAttachedSecretsAreMaskedAtEveryTraversalLevel(t *testing.T) {
	for _, filenames := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "filenames"}[filenames], func(t *testing.T) {
			p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
			if err != nil {
				t.Fatal(err)
			}
			configureAllPseudonymFields(t, p)
			p.ConfigureFilenamePseudonymization(filenames)
			event := map[string]any{"FileName": "mysql.exe", "ProcessCommandLine": `mysql.exe -prootSecret --password "prefix\"tailSecret" --mode safe`}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			out, err := p.PseudonymizeRows(context.Background(), []map[string]any{event, {"Nested": []any{event}, "AdditionalFields": string(encoded)}})
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(out)
			if err := p.Save(); err != nil {
				t.Fatal(err)
			}
			vault, err := os.ReadFile(p.Path())
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"rootSecret", "tailSecret", "prefix"} {
				if strings.Contains(string(body)+string(vault), secret) {
					t.Fatalf("secret %s reached output or vault", secret)
				}
			}
			if !strings.Contains(string(body), "--mode safe") {
				t.Fatal("ordinary options lost")
			}
		})
	}
}
