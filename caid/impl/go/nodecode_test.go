package caid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No file of the Go port, its runners or its tests decodes JSON through
// encoding/json: received text reaches the package only through the strict
// decoder. (json.Number is used as a type, and json.Marshal writes runner
// output; neither decodes.)
func TestNoEncodingJSONDecoding(t *testing.T) {
	banned := []string{"json." + "Unmarshal", "json." + "NewDecoder", "json." + "Decoder", "json." + "Valid("}
	checked := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, b := range banned {
			if strings.Contains(string(data), b) {
				t.Errorf("%s uses %s", path, b)
			}
		}
		return nil
	})
	if err != nil || checked < 10 {
		t.Fatalf("walked %d files: %v", checked, err)
	}
}
