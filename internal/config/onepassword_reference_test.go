package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOnePasswordSecretReference(t *testing.T) {
	valid := []string{
		"op://Personal/YubiTouch/PIN",
		"op://Personal/YubiKey PIV/pin",
		"op://Personal/YubiTouch age recovery/private-key",
		"op://vault/item/section/field",
		"op://Personal/Recovery Item/Key Material/private-key",
		"op://vault/item%2Fname/field%3Fname",
		"op://vault/%E6%B5%8B%E8%AF%95/field",
	}
	for _, reference := range valid {
		t.Run("valid", func(t *testing.T) {
			if err := ValidateOnePasswordSecretReference(reference); err != nil {
				t.Fatalf("valid reference was rejected: %v", err)
			}
		})
	}

	invalid := []string{
		"",
		"vault/item/field",
		"op://vault/item",
		"op://vault/item/section/field/extra",
		"op:///item/field",
		"op://vault//field",
		"op://vault/item/",
		"op://vault/item/field?attribute=otp",
		"op://vault/item/field#fragment",
		"op://vault/item/%zz",
		" op://vault/item/field",
		"op://vault/item/field ",
		"op://vault/item/line%0Abreak",
		"op://vault/item/nul%00byte",
		"op://vault/%20item/field",
		"op://vault/item/field%20",
		"op://vault/item/control%C2%85field",
		"op://vault/item/" + string([]byte{0xff}),
		"op://vault/item/" + strings.Repeat("a", maxOnePasswordSecretReferenceLength),
	}
	for _, reference := range invalid {
		t.Run("invalid", func(t *testing.T) {
			err := ValidateOnePasswordSecretReference(reference)
			if err == nil {
				t.Fatal("invalid reference was accepted")
			}
			if reference != "" && strings.Contains(err.Error(), reference) {
				t.Fatal("validation error exposed the secret reference")
			}
		})
	}
}

func TestProductionDoesNotInvokeSDKSecretReferenceValidator(t *testing.T) {
	for _, root := range []string{filepath.Join("..", "..", "cmd"), filepath.Join("..", "..", "internal")} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "ValidateSecretReference" {
					t.Errorf("production source invokes executable-memory SDK validator: %s", path)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
