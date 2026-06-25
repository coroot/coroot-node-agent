//go:build windows

package metadata

import "net/http"

func newMetadataClient() (*http.Client, func()) {
	return &http.Client{Timeout: metadataServiceTimeout}, func() {}
}
