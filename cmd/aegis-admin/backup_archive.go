package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func openLegacyRegular(name string, limit int64) (*os.File, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("backup input must be a nonempty regular file within its size limit")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, fmt.Errorf("backup input changed while opening")
	}
	return file, nil
}

func extractTarGz(archive, dest string) error {
	file, err := openLegacyRegular(archive, legacyBackupLimit)
	if err != nil {
		return err
	}
	defer file.Close()
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	existing, readErr := directory.ReadDir(-1)
	directory.Close()
	if readErr != nil || len(existing) != 0 {
		return fmt.Errorf("backup extraction requires an empty private directory")
	}
	buffered := bufio.NewReader(io.LimitReader(file, legacyBackupLimit+1))
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return err
	}
	defer compressed.Close()
	compressed.Multistream(false)
	expanded := &io.LimitedReader{R: compressed, N: legacyBackupLimit + (64 << 10) + 1}
	reader := tar.NewReader(expanded)
	seen := map[string]bool{}
	var payloadSize int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		limit, known := legacyEntryLimits[header.Name]
		if !known || seen[header.Name] || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return fmt.Errorf("unknown, duplicate or non-regular backup entry")
		}
		if header.Size <= 0 || header.Size > limit || payloadSize > legacyBackupLimit-header.Size {
			return fmt.Errorf("backup entry or expanded payload exceeds size limit")
		}
		seen[header.Name] = true
		payloadSize += header.Size
		output, err := root.OpenFile(header.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(output, reader, header.Size)
		syncErr := output.Sync()
		closeErr := output.Close()
		for _, err := range []error{copyErr, syncErr, closeErr} {
			if err != nil {
				return fmt.Errorf("extract backup entry: %w", err)
			}
		}
	}
	if !seen["data.db"] || !seen["manifest.json"] {
		return fmt.Errorf("backup requires data.db and manifest.json")
	}
	// Reading through the gzip trailer validates its CRC. Only bounded zero tar
	// padding is accepted; concatenated gzip streams and hidden trailing data fail.
	padding, err := io.ReadAll(io.LimitReader(expanded, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(padding) > 64<<10 || expanded.N == 0 || len(bytes.Trim(padding, "\x00")) != 0 {
		return fmt.Errorf("invalid or excessive archive trailing data")
	}
	if _, err := buffered.ReadByte(); err != io.EOF {
		return fmt.Errorf("backup has trailing compressed data")
	}
	return nil
}

func verifyManifest(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := openLegacyRegular(filepath.Join(dir, "manifest.json"), legacyEntryLimits["manifest.json"])
	if err != nil {
		return fmt.Errorf("manifest missing or invalid: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, legacyEntryLimits["manifest.json"]+1))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("manifest must be a JSON object")
	}
	manifest := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid manifest key")
		}
		name, ok := token.(string)
		if !ok || (name != "data.db" && name != "config.yaml") || manifest[name] != "" {
			return fmt.Errorf("unknown or duplicate manifest entry")
		}
		var digest string
		if err := decoder.Decode(&digest); err != nil {
			return fmt.Errorf("invalid manifest digest")
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
			return fmt.Errorf("manifest digest must be a lowercase SHA-256")
		}
		manifest[name] = digest
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("invalid manifest object")
	}
	if _, err := decoder.Token(); err != io.EOF || manifest["data.db"] == "" {
		return fmt.Errorf("manifest requires a database checksum and no trailing JSON")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	files, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return err
	}
	if len(files) != len(manifest)+1 {
		return fmt.Errorf("manifest does not cover the complete backup payload")
	}
	for _, entry := range files {
		name := entry.Name()
		if name == "manifest.json" {
			continue
		}
		expected, known := manifest[name]
		if !known || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected recovery file")
		}
		input, err := openLegacyRegular(filepath.Join(dir, name), legacyEntryLimits[name])
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(input, legacyEntryLimits[name]+1))
		input.Close()
		if err != nil || n > legacyEntryLimits[name] || hex.EncodeToString(hash.Sum(nil)) != expected {
			return fmt.Errorf("%s checksum mismatch or invalid size", name)
		}
	}
	return nil
}
