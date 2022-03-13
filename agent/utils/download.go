package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

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

// TODO: io.Copy to file to use minium memory
func Download(ctx context.Context, dst string, sha256sum string, urls []string, suffix string) (err error) {
	var (
		checksum []byte
	)
	// check wheater this already exist
	if checksum, err = hex.DecodeString(sha256sum); err != nil {
		return
	}
	hasher := sha256.New()
	// extra work, but to simplify
	if err = CheckSignature(dst, sha256sum); err == nil {
		return
	}
	// in elkeid, `defer` in loop... emmm, not a best practice I think, but nothing wrong
	for _, rawurl := range urls {
		var req *http.Request
		var resp *http.Response
		subctx, cancel := context.WithTimeout(ctx, time.Minute*3)
		defer cancel()
		if req, err = http.NewRequestWithContext(subctx, "GET", rawurl, nil); err != nil {
			continue
		}
		if resp, err = http.DefaultClient.Do(req); err != nil {
			continue
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			err = errors.New("http error: " + resp.Status)
			continue
		}
		defer resp.Body.Close()
		var buf []byte
		// @Notes: ReadAll may not be a best practice, but a dump to mem/file is needed
		// So, the filesize is limited! Another option is to download and io.Copy to file
		// @Reference: https://stackoverflow.com/questions/11692860/how-can-i-efficiently-download-a-large-file-using-go
		if buf, err = ioutil.ReadAll(resp.Body); err != nil {
			continue
		}
		hasher.Reset()
		hasher.Write(buf)
		if !bytes.Equal(hasher.Sum(nil), checksum) {
			err = errors.New("checksum doesn't match")
			continue
		}
		br := bytes.NewBuffer(buf)
		switch suffix {
		case "tar.gz":
			err = DecompressTarGz(dst, br)
		default:
			err = DecompressDefault(dst, br)
		}
		break
	}
	return
}
