package goNessus

import (
	"io"
	"os"
)

func CopyFile(source, dest string) (int64, error) {
	source_file, err := os.Open(source)
	if err != nil {
		return 0, err
	}
	defer source_file.Close()

	dest_file, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	defer dest_file.Close()
	return io.Copy(dest_file, source_file)
}
