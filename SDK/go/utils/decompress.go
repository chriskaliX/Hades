package util

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

func DecompressTarGz(dst string, r io.Reader) (err error) {
	var gr *gzip.Reader
	gr, err = gzip.NewReader(r)
	if err != nil {
		return
	}
	tr := tar.NewReader(gr)
	root := filepath.Dir(dst)
	err = os.MkdirAll(root, 0o0701)
	if err != nil {
		return
	}
	os.Chmod(root, 0o0701)
	defer func() {
		if err != nil {
			os.RemoveAll(root)
		}
	}()
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		switch {
		case err == io.EOF:
			err = nil
			return
		case err != nil:
			return
		}
		target := filepath.Join(root, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		// if it's a file create it
		case tar.TypeReg:
			var f *os.File
			if f, err = os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode)); err != nil {
				return
			}
			// copy over contents
			if _, err = io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
}
func DecompressDefault(dst string, r io.Reader) (err error) {
	var f *os.File
	root := filepath.Dir(dst)
	if err = os.MkdirAll(root, 0o0700); err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.RemoveAll(root)
		}
	}()

	if f, err = os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0700); err != nil {
		return
	}
	defer f.Close()
	if _, err = io.Copy(f, r); err != nil {
		return err
	}
	return
}
