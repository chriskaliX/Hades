package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
)

// Download function to download executable or gzip or remote server
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
	// In Elkeid v1.9.1, only Timeout is different from DefaultTransport
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Minute * 10,
	}
	for _, rawurl := range urls {
		var req *http.Request
		var resp *http.Response
		subctx, cancel := context.WithTimeout(ctx, time.Minute*3)
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
		// Before Elkeid v1.9.1, ioutil.ReadAll is used and it may
		// lead memory grows rapidly since it reads everything into
		// memeory, using io.TeeReader to both read from Reader and
		// calculate the hash
		// Also the decompress should change
		resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
		hasher.Reset()
		r := io.TeeReader(resp.Body, hasher)
		switch suffix {
		case "tar.gz":
			err = DecompressTarGz(dst, r)
		default:
			err = DecompressDefault(dst, r)
		}
		resp.Body.Close()
		if err == nil {

		}
		break
	}
	return
}

func CheckSignature(dst string, sign string) (err error) {
	var (
		f         *os.File
		signBytes []byte
	)
	if f, err = os.Open(dst); err != nil {
		return
	}
	defer f.Close()

	if signBytes, err = hex.DecodeString(sign); err != nil {
		return
	}
	hasher := sha256.New()
	// @Reference: https://pandaychen.github.io/2020/01/01/MAGIC-GO-IO-PACKAGE/
	if _, err = io.Copy(hasher, f); err != nil {
		return
	}
	if !bytes.Equal(hasher.Sum(nil), signBytes) {
		err = errors.New("signature doesn't match")
		return
	}
	// make it executable
	f.Chmod(0o0700)
	return
}
