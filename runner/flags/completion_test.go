package flags

import (
	"strings"
	"testing"

	"github.com/lynxsecurity/pflag"
)

func testFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("gau", pflag.ContinueOnError)
	fs.String("o", "", "filename to write results to")
	fs.String("config", "", "config file")
	fs.StringSlice("providers", nil, "providers [list]")
	fs.Bool("verbose", false, "it's verbose")
	fs.String("completion", "", "shell")
	fs.String("test.v", "", "hidden test flag")
	return fs
}

func TestCompletionScripts(t *testing.T) {
	fs := testFlagSet()
	for _, shell := range CompletionShells {
		out, err := Completion(shell, fs)
		if err != nil {
			t.Fatalf("%s: %v", shell, err)
		}
		for _, want := range []string{"--o", "--config", "--providers", "--verbose", "--completion"} {
			if shell == "fish" {
				want = strings.TrimPrefix(want, "--")
			}
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q", shell, want)
			}
		}
		if strings.Contains(out, "test.v") {
			t.Errorf("%s: leaked test flag", shell)
		}
		for _, p := range ProviderNames {
			if !strings.Contains(out, p) {
				t.Errorf("%s: missing provider %q", shell, p)
			}
		}
		if !strings.HasSuffix(out, "\n") {
			t.Errorf("%s: no trailing newline", shell)
		}
	}
}

func TestCompletionShIsBash(t *testing.T) {
	fs := testFlagSet()
	sh, _ := Completion("sh", fs)
	bash, _ := Completion("bash", fs)
	if sh != bash {
		t.Fatal("sh script differs from bash script")
	}
}

func TestCompletionUnknownShell(t *testing.T) {
	if _, err := Completion("nope", testFlagSet()); err == nil {
		t.Fatal("expected error for unknown shell")
	}
}
