//go:build !unix

package cli

import (
	"errors"
	"log/slog"
	"os"
)

// captureFd2 isn't done here: standard error stays the terminal's.
func captureFd2(*slog.Logger) (*os.File, func(), error) {
	return nil, nil, errors.New("not on this platform")
}
