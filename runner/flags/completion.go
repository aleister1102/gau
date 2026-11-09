package flags

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lynxsecurity/pflag"
)

// ProviderNames lists every value accepted by --providers.
var ProviderNames = []string{
	"wayback", "commoncrawl", "otx", "urlscan", "arquivopt", "ghostarchive",
	"virustotal", "leakix", "brave", "serpapi", "firecrawl", "intelx",
}

// CompletionShells lists every value accepted by --completion.
var CompletionShells = []string{"bash", "zsh", "fish", "sh"}

type valueKind int

const (
	kindNone valueKind = iota
	kindFile
	kindProviders
	kindShells
)

type flagInfo struct {
	name    string
	usage   string
	boolean bool
	kind    valueKind
}

func kindOf(name string) valueKind {
	switch name {
	case "providers":
		return kindProviders
	case "config", "o":
		return kindFile
	case "completion":
		return kindShells
	}
	return kindNone
}

func collectFlags(fs *pflag.FlagSet) []flagInfo {
	var out []flagInfo
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || strings.HasPrefix(f.Name, "test.") {
			return
		}
		out = append(out, flagInfo{
			name:    f.Name,
			usage:   f.Usage,
			boolean: f.NoOptDefVal != "",
			kind:    kindOf(f.Name),
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// Completion returns the completion script for shell. The sh script is the
// bash script: POSIX sh has no completion system of its own.
func Completion(shell string, fs *pflag.FlagSet) (string, error) {
	infos := collectFlags(fs)
	switch shell {
	case "bash", "sh":
		return bashScript(infos), nil
	case "zsh":
		return zshScript(infos), nil
	case "fish":
		return fishScript(infos), nil
	}
	return "", fmt.Errorf("unsupported shell %q (want one of: %s)", shell, strings.Join(CompletionShells, ", "))
}

func bashScript(infos []flagInfo) string {
	var names []string
	for _, f := range infos {
		names = append(names, "--"+f.name)
	}

	var b strings.Builder
	b.WriteString("# bash completion for gau (also used for sh)\n")
	b.WriteString("_gau() {\n")
	b.WriteString("    local cur prev\n")
	b.WriteString("    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	b.WriteString("    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n")
	b.WriteString("    if [[ $cur == \"=\" ]]; then cur=\"\"; fi\n")
	b.WriteString("    if [[ $prev == \"=\" ]]; then prev=\"${COMP_WORDS[COMP_CWORD-2]}\"; fi\n")
	b.WriteString("    case \"$prev\" in\n")
	for _, f := range infos {
		if f.boolean {
			continue
		}
		fmt.Fprintf(&b, "    --%s)\n", f.name)
		switch f.kind {
		case kindProviders:
			b.WriteString("        local prefix=\"\" last=\"$cur\"\n")
			b.WriteString("        if [[ $cur == *,* ]]; then prefix=\"${cur%,*},\"; last=\"${cur##*,}\"; fi\n")
			fmt.Fprintf(&b, "        COMPREPLY=( $(compgen -P \"$prefix\" -W %q -- \"$last\") )\n", strings.Join(ProviderNames, " "))
			b.WriteString("        compopt -o nospace 2>/dev/null\n")
		case kindFile:
			b.WriteString("        compopt -o filenames 2>/dev/null\n")
			b.WriteString("        COMPREPLY=( $(compgen -f -- \"$cur\") )\n")
		case kindShells:
			fmt.Fprintf(&b, "        COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(CompletionShells, " "))
		}
		b.WriteString("        return 0\n        ;;\n")
	}
	b.WriteString("    esac\n")
	b.WriteString("    if [[ $cur == -* ]]; then\n")
	fmt.Fprintf(&b, "        COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(names, " "))
	b.WriteString("    fi\n")
	b.WriteString("}\n")
	b.WriteString("complete -F _gau gau\n")
	return b.String()
}

func zshQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`, `'`, `'\''`)
	return r.Replace(s)
}

func zshScript(infos []flagInfo) string {
	var b strings.Builder
	b.WriteString("#compdef gau\n")
	b.WriteString("_gau() {\n")
	b.WriteString("    _arguments -s \\\n")
	for _, f := range infos {
		spec := "--" + f.name
		usage := zshQuote(f.usage)
		if f.boolean {
			fmt.Fprintf(&b, "        '%s[%s]' \\\n", spec, usage)
			continue
		}
		var action string
		switch f.kind {
		case kindProviders:
			action = ":providers:_values -s , provider " + strings.Join(ProviderNames, " ")
		case kindFile:
			action = ":file:_files"
		case kindShells:
			action = ":shell:(" + strings.Join(CompletionShells, " ") + ")"
		default:
			action = ":value: "
		}
		fmt.Fprintf(&b, "        '%s=[%s]%s' \\\n", spec, usage, action)
	}
	b.WriteString("        '*:domain: '\n")
	b.WriteString("}\n")
	b.WriteString("if [ \"$funcstack[1]\" = \"_gau\" ]; then\n")
	b.WriteString("    _gau \"$@\"\n")
	b.WriteString("else\n")
	b.WriteString("    compdef _gau gau\n")
	b.WriteString("fi\n")
	return b.String()
}

func fishQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

func fishScript(infos []flagInfo) string {
	var b strings.Builder
	b.WriteString("# fish completion for gau\n")
	b.WriteString("function __gau_providers\n")
	b.WriteString("    set -l tok (string replace -r -- '^--[^=]*=' '' (commandline -ct))\n")
	b.WriteString("    set -l prefix ''\n")
	b.WriteString("    if string match -q -- '*,*' $tok\n")
	b.WriteString("        set prefix (string replace -r -- '[^,]*$' '' $tok)\n")
	b.WriteString("    end\n")
	fmt.Fprintf(&b, "    for p in %s\n", strings.Join(ProviderNames, " "))
	b.WriteString("        echo $prefix$p\n")
	b.WriteString("    end\n")
	b.WriteString("end\n")
	b.WriteString("complete -c gau -f\n")
	for _, f := range infos {
		line := fmt.Sprintf("complete -c gau -l %s", f.name)
		if !f.boolean {
			switch f.kind {
			case kindProviders:
				line += " -x -a '(__gau_providers)'"
			case kindFile:
				line += " -r -F"
			case kindShells:
				line += " -x -a '" + strings.Join(CompletionShells, " ") + "'"
			default:
				line += " -x"
			}
		}
		line += fmt.Sprintf(" -d '%s'", fishQuote(f.usage))
		b.WriteString(line + "\n")
	}
	return b.String()
}
