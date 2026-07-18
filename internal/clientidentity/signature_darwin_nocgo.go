//go:build darwin && !cgo

package clientidentity

func codeSignatureValid(int) bool {
	return false
}
