//go:build !darwin

package ageipc

import (
	"errors"
	"net"
)

func platformPeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials are unsupported on this platform")
}
