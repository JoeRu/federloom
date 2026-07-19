// Command validate-examples strict-decodes every example config and rules file
// against the current schemas. Unknown keys are errors — this is the CI gate
// that keeps published examples from rotting as the config schema evolves.
//
// Usage: go run ./tools/validate-examples <dir> [<dir>...]
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-examples <dir> [<dir>...]")
		os.Exit(2)
	}
	failures := 0
	checked := 0
	for _, root := range os.Args[1:] {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if !isCandidate(path) {
				return nil
			}
			checked++
			if verr := validateFile(path); verr != nil {
				fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, verr)
				failures++
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL walking %s: %v\n", root, err)
			failures++
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Printf("validate-examples: %d files OK\n", checked)
}

func isCandidate(path string) bool {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
		return false
	}
	return strings.HasPrefix(base, "config") || strings.HasPrefix(base, "rules")
}

// validateFile strict-decodes config*.yaml against config.Config and
// rules*.yaml against []rules.Rule. Files matching neither prefix are skipped.
func validateFile(path string) error {
	base := filepath.Base(path)
	switch {
	case !isCandidate(path):
		return nil
	case strings.HasPrefix(base, "config"):
		return strictDecode(path, &config.Config{})
	default: // rules*
		return strictDecode(path, &[]rules.Rule{})
	}
}

func strictDecode(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
