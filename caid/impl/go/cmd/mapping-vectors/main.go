// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	caidlib "caid"
)

type SideDescriptor struct {
	Source         string `json:"source"`
	Profile        string `json:"profile"`
	Pin            string `json:"pin"`
	NativeVerified *bool  `json:"native_verified"`
}

type Mutation struct {
	Side   string      `json:"side"`
	Target string      `json:"target"`
	Op     string      `json:"op"`
	Path   string      `json:"path"`
	Value  interface{} `json:"value"`
}

type Expectation struct {
	Verdict        string   `json:"verdict"`
	Reasons        []string `json:"reasons"`
	ReasonContains string   `json:"reason_contains"`
}

type Vector struct {
	ID                 string         `json:"id"`
	Left               SideDescriptor `json:"left"`
	Right              SideDescriptor `json:"right"`
	Mutations          []Mutation     `json:"mutations"`
	RepinAfterMutation []string       `json:"repin_after_mutation"`
	Expect             Expectation    `json:"expect"`
}

type Corpus struct {
	Version     string                            `json:"@version"`
	Suite       string                            `json:"suite"`
	Definitions []interface{}                     `json:"definitions"`
	Profiles    map[string]map[string]interface{} `json:"profiles"`
	Sources     map[string]map[string]interface{} `json:"sources"`
	Vectors     []Vector                          `json:"vectors"`
}

type Output struct {
	ID      string   `json:"id"`
	Pass    bool     `json:"pass"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}

func clone(value interface{}) interface{} {
	data, _ := json.Marshal(value)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var out interface{}
	if err := decoder.Decode(&out); err != nil {
		panic(err)
	}
	return out
}

func pointerSegments(pointer string) []string {
	raw := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		out = append(out, strings.ReplaceAll(strings.ReplaceAll(item, "~1", "/"), "~0", "~"))
	}
	return out
}

func mutate(value interface{}, segments []string, operation Mutation) interface{} {
	if len(segments) == 0 {
		if operation.Op == "set" {
			return clone(operation.Value)
		}
		return nil
	}
	head := segments[0]
	if len(segments) == 1 {
		switch typed := value.(type) {
		case map[string]interface{}:
			if operation.Op == "delete" {
				delete(typed, head)
			} else if operation.Op == "set" {
				typed[head] = clone(operation.Value)
			} else {
				panic("unsupported vector mutation: " + operation.Op)
			}
			return typed
		case []interface{}:
			index, err := strconv.Atoi(head)
			if err != nil || index < 0 || index >= len(typed) {
				panic("invalid vector array mutation")
			}
			if operation.Op == "delete" {
				return append(typed[:index], typed[index+1:]...)
			}
			if operation.Op == "set" {
				typed[index] = clone(operation.Value)
				return typed
			}
			panic("unsupported vector mutation: " + operation.Op)
		default:
			panic("invalid vector mutation target")
		}
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		typed[head] = mutate(typed[head], segments[1:], operation)
		return typed
	case []interface{}:
		index, err := strconv.Atoi(head)
		if err != nil || index < 0 || index >= len(typed) {
			panic("invalid vector array path")
		}
		typed[index] = mutate(typed[index], segments[1:], operation)
		return typed
	default:
		panic("invalid vector mutation path")
	}
}

func buildSide(corpus Corpus, descriptor SideDescriptor) map[string]interface{} {
	profile := clone(corpus.Profiles[descriptor.Profile]).(map[string]interface{})
	source := clone(corpus.Sources[descriptor.Source]).(map[string]interface{})
	sourceDescriptor := clone(profile["source_format"]).(map[string]interface{})
	pin := descriptor.Pin
	if pin == "profile" {
		pin = caidlib.MappingProfileHash(profile)
	}
	nativeVerified := true
	if descriptor.NativeVerified != nil {
		nativeVerified = *descriptor.NativeVerified
	}
	return map[string]interface{}{
		"source":                source,
		"profile":               profile,
		"source_descriptor":     sourceDescriptor,
		"expected_profile_hash": pin,
		"native_verified":       nativeVerified,
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func main() {
	vectorPath := filepath.Clean(filepath.Join("..", "..", "conformance", "mapping-vectors.json"))
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var corpus Corpus
	if err := decoder.Decode(&corpus); err != nil {
		panic(err)
	}

	output := []Output{}
	for _, vector := range corpus.Vectors {
		left := buildSide(corpus, vector.Left)
		right := buildSide(corpus, vector.Right)
		for _, operation := range vector.Mutations {
			side := left
			if operation.Side == "right" {
				side = right
			}
			side[operation.Target] = mutate(side[operation.Target], pointerSegments(operation.Path), operation)
		}
		for _, sideName := range vector.RepinAfterMutation {
			side := left
			if sideName == "right" {
				side = right
			}
			profile, _ := side["profile"].(map[string]interface{})
			side["expected_profile_hash"] = caidlib.MappingProfileHash(profile)
		}
		result := caidlib.CompareMappedActions(left, right, corpus.Definitions, corpus.Suite)
		verdictOK := result.Verdict == vector.Expect.Verdict
		reasonsOK := equalStrings(result.Reasons, vector.Expect.Reasons)
		if vector.Expect.ReasonContains != "" {
			reasonsOK = contains(result.Reasons, vector.Expect.ReasonContains)
		}
		output = append(output, Output{
			ID: vector.ID, Pass: verdictOK && reasonsOK,
			Verdict: result.Verdict, Reasons: result.Reasons,
		})
	}

	jsonMode := false
	for _, arg := range os.Args[1:] {
		if arg == "--json" {
			jsonMode = true
		}
	}
	failed := false
	if jsonMode {
		encoded, _ := json.Marshal(output)
		fmt.Println(string(encoded))
	} else {
		for _, result := range output {
			status := "PASS"
			if !result.Pass {
				status = "FAIL"
				failed = true
			}
			fmt.Println(status, result.ID, result.Verdict)
		}
	}
	for _, result := range output {
		if !result.Pass {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
