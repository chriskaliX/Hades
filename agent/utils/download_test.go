package utils

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

const path = "http://127.0.0.1:8000/collector"

func BenchmarkDownloadOld(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rawurl := path
		req, err := http.NewRequest("GET", rawurl, nil)
		if err != nil {
			b.Error(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Error(err)
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			err = errors.New("http error: " + resp.Status)
			b.Error(err)
		}
		defer resp.Body.Close()
		var buf []byte
		buf, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			b.Error(err)
		}
		hasher := sha256.New()
		hasher.Reset()
		hasher.Write(buf)
		_ = hasher.Sum(nil)
		br := bytes.NewBuffer(buf)
		f, err := os.OpenFile("/tmp/download_test", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0700)
		if err != nil {
			b.Error(err)
		}
		if _, err = io.Copy(f, br); err != nil {
			b.Error(err)
		}
		f.Close()
	}
}

func BenchmarkDownloadNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rawurl := path
		req, err := http.NewRequest("GET", rawurl, nil)
		if err != nil {
			b.Error(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Error(err)
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			err = errors.New("http error: " + resp.Status)
			b.Error(err)
		}
		defer resp.Body.Close()
		hasher := sha256.New()
		hasher.Reset()
		r := io.TeeReader(resp.Body, hasher)
		f, err := os.OpenFile("/tmp/download_test", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0700)
		if err != nil {
			b.Error(err)
		}
		if _, err = io.Copy(f, r); err != nil {
			b.Error(err)
		}
		f.Close()
	}
}
