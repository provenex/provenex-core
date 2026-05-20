// Provenex Go client example.
//
// Demonstrates the Pattern B / Pattern C deployment shape: a non-Python
// caller (this Go program) hits the Provenex HTTP API, receives a
// signed provenance receipt, and verifies the receipt offline using
// only the shared HMAC secret. No Provenex SDK is needed on the Go
// side; only stdlib + JSON.
//
// Build + run:
//
//	cd examples/go_client
//	go run main.go
//
// The program targets http://localhost:8080 by default. Override with
// PROVENEX_SERVER_URL. The HMAC verification secret must match the
// server's PROVENEX_RECEIPT_SECRET; we read it from
// PROVENEX_RECEIPT_SECRET on the Go side too for simplicity.
//
// For the Ed25519 path (production default), swap the
// verifyReceiptHMAC function for a verifyReceiptEd25519 that
// loads the public key PEM and uses ed25519.Verify on the same
// canonical payload. The canonicalisation (sort keys, separators,
// drop signature) is identical for both signers. The
// receipt.signature.algorithm string for that path is "ed25519".

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// VerifyRequest matches the /v1/verify request body.
type VerifyRequest struct {
	Chunks      []string `json:"chunks"`
	RequestText string   `json:"request_text,omitempty"`
}

// VerifyResponse matches the /v1/verify response body.
type VerifyResponse struct {
	Kept    []string               `json:"kept"`
	Blocked []string               `json:"blocked"`
	Receipt map[string]interface{} `json:"receipt"`
}

func main() {
	base := os.Getenv("PROVENEX_SERVER_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	secret := os.Getenv("PROVENEX_RECEIPT_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "PROVENEX_RECEIPT_SECRET must be set to the server's HMAC secret.")
		os.Exit(2)
	}

	// 1. Ingest a chunk so the verify call returns VERIFIED.
	chunk := "hello from the Go client"
	if err := ingest(base, chunk); err != nil {
		fmt.Fprintf(os.Stderr, "ingest failed: %v\n", err)
		os.Exit(1)
	}

	// 2. Verify it.
	resp, err := verify(base, []string{chunk})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("server kept: %v\n", resp.Kept)

	// 3. Verify the receipt signature OFFLINE, with only the HMAC secret.
	//    Real-world: the Go service would persist receipt JSON in audit
	//    storage and re-verify on demand.
	if err := verifyReceiptHMAC(resp.Receipt, secret); err != nil {
		fmt.Fprintf(os.Stderr, "OFFLINE verify FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("offline signature verification: PASS")
}

// ingest posts one (fingerprint, doc) pair into the Postgres index.
func ingest(base, text string) error {
	fp := "sha256:" + hexSHA256([]byte(text))
	docVer := "sha256:" + hexSHA256([]byte("doc-1-v1"))
	body := map[string]interface{}{
		"entries": []map[string]interface{}{
			{
				"fingerprint":      fp,
				"document_id":      "doc-1",
				"document_version": docVer,
				"chunk_offset":     0,
				"chunk_length":     len(text),
			},
		},
	}
	return postJSON(base+"/v1/ingest", body, nil)
}

// verify calls /v1/verify and returns the parsed response.
func verify(base string, chunks []string) (*VerifyResponse, error) {
	req := VerifyRequest{Chunks: chunks, RequestText: "Go client integration test"}
	var resp VerifyResponse
	if err := postJSON(base+"/v1/verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// verifyReceiptHMAC reproduces the canonical-JSON payload the Python
// signer computed at issue time and re-checks the HMAC-SHA256
// signature.
//
// Canonical payload = JSON-encoded receipt with:
//   - "signature" field removed
//   - keys sorted (recursively)
//   - separators ',' and ':' (no whitespace)
//   - UTF-8, non-ASCII preserved (no \uXXXX escapes)
//
// Identical to provenex/core/receipt.py::verify_receipt_signature.
func verifyReceiptHMAC(receipt map[string]interface{}, secret string) error {
	sigField, ok := receipt["signature"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("receipt missing signature block")
	}
	alg, _ := sigField["algorithm"].(string)
	if alg != "hmac-sha256" {
		return fmt.Errorf("expected hmac-sha256 signer, got %q", alg)
	}
	expected, _ := sigField["value"].(string)
	if expected == "" {
		return fmt.Errorf("receipt signature has no value")
	}

	payload := stripSignatureAndCanonicalise(receipt)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	got := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(expected)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// stripSignatureAndCanonicalise returns the canonical-JSON bytes the
// signer hashed at issue time.
func stripSignatureAndCanonicalise(in map[string]interface{}) []byte {
	cp := make(map[string]interface{}, len(in))
	for k, v := range in {
		if k == "signature" {
			continue
		}
		cp[k] = v
	}
	return canonicalJSON(cp)
}

// canonicalJSON mirrors the Python json.dumps(sort_keys=True,
// separators=(',', ':'), ensure_ascii=False) shape. We re-encode
// every map with sorted keys; non-map types serialize unchanged.
func canonicalJSON(v interface{}) []byte {
	var b bytes.Buffer
	writeCanonical(&b, v)
	return b.Bytes()
}

func writeCanonical(b *bytes.Buffer, v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			writeCanonical(b, t[k])
		}
		b.WriteByte('}')
	case []interface{}:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, el)
		}
		b.WriteByte(']')
	default:
		// Delegate to encoding/json for atoms (string, bool, float64, nil).
		// The Python producer uses ensure_ascii=False, but the JSON spec
		// already permits unescaped UTF-8 above U+007E; Go's encoding/json
		// matches that, with the caveat that it escapes <, >, & to
		// < etc. unless SetEscapeHTML(false) is requested.
		enc := json.NewEncoder(b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(t)
		// json.Encoder writes a trailing newline we don't want.
		if b.Len() > 0 && b.Bytes()[b.Len()-1] == '\n' {
			b.Truncate(b.Len() - 1)
		}
	}
}

func writeJSONString(b *bytes.Buffer, s string) {
	out, _ := json.Marshal(s)
	b.Write(out)
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func postJSON(url string, body, out interface{}) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
