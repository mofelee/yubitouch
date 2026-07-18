//go:build !darwin

package clientidentity

import (
	"net"

	"github.com/mofelee/yubitouch/internal/signing"
)

func Resolve(net.Conn) signing.Requester {
	return signing.Requester{Name: unknownRequester}
}
