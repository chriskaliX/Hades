package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

var downloadTimeout = 10 * time.Minute

// Download function to download executable or gzip or remote server
// From Elkeid v1.9.1
//
// Elkeid v1.9.1 enhance this function by setting a more robust http client
// configuration and also the reader part
//
// var DefaultTransport RoundTripper = &Transport{
// 	Proxy: ProxyFromEnvironment,
// 	DialContext: (&net.Dialer{
// 			Timeout:   30 * time.Second,
// 			KeepAlive: 30 * time.Second,
// 	}).DialContext,
// 	ForceAttemptHTTP2:     true,
// 	MaxIdleConns:          100,
// 	IdleConnTimeout:       90 * time.Second,
// 	TLSHandshakeTimeout:   10 * time.Second,
// 	ExpectContinueTimeout: 1 * time.Second,
// }
//
// https://github.com/golang/go/blob/b2faff18ce28edad98303d2c3134dec1331fd7b5/src/net/http/transport.go
func Download(ctx context.Context, dst string, sha256sum string, urls []string, suffix string) (err error) {
	var checksum []byte
	// check wheater this already exist
	if checksum, err = hex.DecodeString(sha256sum); err != nil {
		return
	}
	hasher := sha256.New()
	if err = CheckSignature(dst, sha256sum); err == nil {
		return
	}
	// In Elkeid v1.9.1, only Timeout is different from DefaultTransport.
	// Before v1.9.1 the timeout was controlled by subctx, now it is
	// controlled by client itself.
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   downloadTimeout,
	}
	for _, rawurl := range urls {
		var req *http.Request
		var resp *http.Response
		subctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if req, err = http.NewRequestWithContext(subctx, "GET", rawurl, nil); err != nil {
			continue
		}
		if resp, err = client.Do(req); err != nil {
			continue
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			err = errors.New("http error: " + resp.Status)
			continue
		}
		// Set the limitation of download, but I think it would be alright
		// since the time limitation is also set. This configration helps
		// avoid download too much to fill up the disk even within 10 mins.
		resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
		hasher.Reset()
		// Before Elkeid v1.9.1, ioutil.ReadAll is used and it may
		// lead memory grows rapidly since it reads everything into
		// memeory, using io.TeeReader to both read from Reader and
		// calculate the hash
		// Also the decompress should be updated
		r := io.TeeReader(resp.Body, hasher)
		switch suffix {
		case "tar.gz":
			err = DecompressTarGz(dst, r)
		default:
			err = DecompressDefault(dst, r)
		}
		resp.Body.Close()
		if err != nil {
			continue
		}
		if c := hex.EncodeToString(hasher.Sum(nil)); c != sha256sum {
			err = fmt.Errorf("checksum doesn't match: %s vs %s", checksum, sha256sum)
			zap.S().Error(err)
		} else {
			break
		}
	}
	return
}

// CheckSignature checks the dst and sign for local usage
func CheckSignature(dst string, sign string) error {
	f, err := os.Open(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	signBytes, err := hex.DecodeString(sign)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, f); err != nil {
		return err
	}
	if !bytes.Equal(hasher.Sum(nil), signBytes) {
		err = errors.New("signature doesn't match")
		return err
	}
	f.Chmod(0o0700)
	return nil
}
