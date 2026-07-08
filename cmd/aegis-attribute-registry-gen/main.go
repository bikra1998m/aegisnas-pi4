package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const maxRegistryBytes = 32 << 20

func main() {
	input := flag.String("input", "", "source audit CSV")
	output := flag.String("output", "", "generated registry CSV")
	check := flag.Bool("check", false, "verify output is current without writing")
	expectedSHA := flag.String("expected-sha256", "", "optional expected source SHA-256")
	flag.Parse()

	if *input == "" || *output == "" {
		fatalf("-input and -output are required")
	}
	payload, err := readBounded(*input)
	if err != nil {
		fatalf("read source registry: %v", err)
	}
	digest := sha256.Sum256(payload)
	actualSHA := hex.EncodeToString(digest[:])
	if *expectedSHA != "" && *expectedSHA != actualSHA {
		fatalf("source registry SHA-256 is %s, expected %s", actualSHA, *expectedSHA)
	}
	registry, err := productconfigs.ParseAttributeRegistryCSV(payload)
	if err != nil {
		fatalf("validate source registry: %v", err)
	}
	if registry.SourceAttributeCount != 7654 || registry.SourceFileCount != 246 {
		fatalf("source registry contract changed: got %d attributes from %d files", registry.SourceAttributeCount, registry.SourceFileCount)
	}

	if *check {
		current, err := os.ReadFile(*output)
		if err != nil {
			fatalf("read generated registry: %v", err)
		}
		if !bytes.Equal(current, payload) {
			fatalf("generated registry is stale; run go generate ./configs")
		}
		fmt.Printf("attribute registry verified: release=%s files=%d source_attributes=%d sha256=%s\n",
			registry.SourceRelease, registry.SourceFileCount, registry.SourceAttributeCount, actualSHA)
		return
	}
	if err := writeAtomic(*output, payload); err != nil {
		fatalf("write generated registry: %v", err)
	}
	fmt.Printf("attribute registry generated: release=%s files=%d source_attributes=%d sha256=%s\n",
		registry.SourceRelease, registry.SourceFileCount, registry.SourceAttributeCount, actualSHA)
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	payload, err := io.ReadAll(io.LimitReader(f, maxRegistryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxRegistryBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxRegistryBytes)
	}
	return payload, nil
}

func writeAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".attribute-registry-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
