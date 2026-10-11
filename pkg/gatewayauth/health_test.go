package gatewayauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testChallengeHeader = "X-Fak-Auth-Challenge"
	testProofHeader     = "X-Fak-Auth-Proof"
)

func validChallenge(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}

func expectedProof(key, encodedChallenge string) string {
	nonce, _ := base64.StdEncoding.DecodeString(encodedChallenge)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("fak-health-v1\x00"))
	mac.Write(nonce)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestWriteHealthProof(t *testing.T) {
	valid := validChallenge(t)
	cases := []struct {
		name      string
		key       string
		challenge string
		wantProof bool
	}{
		{"valid challenge and key", "test-key", valid, true},
		{"empty key leaves header unset", "", valid, false},
		{"missing challenge leaves header unset", "test-key", "", false},
		{"non-base64 challenge leaves header unset", "test-key", "not-base64!!", false},
		{"short nonce leaves header unset", "test-key", base64.StdEncoding.EncodeToString([]byte("short")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.challenge != "" {
				req.Header.Set(testChallengeHeader, tc.challenge)
			}
			rec := httptest.NewRecorder()
			WriteHealthProof(rec, req, tc.key)
			got := rec.Header().Get(testProofHeader)
			if tc.wantProof {
				if got == "" {
					t.Fatalf("proof header unset, want set")
				}
				if want := expectedProof(tc.key, tc.challenge); got != want {
					t.Fatalf("proof = %q, want %q", got, want)
				}
			} else if got != "" {
				t.Fatalf("proof = %q, want unset", got)
			}
		})
	}
}

func TestWriteHealthProofLeavesStatusAndBodyUntouched(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testChallengeHeader, validChallenge(t))
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusTeapot)
	rec.Body.WriteString("body")
	WriteHealthProof(rec, req, "test-key")
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if rec.Body.String() != "body" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "body")
	}
}

func TestServeKeyProof(t *testing.T) {
	valid := validChallenge(t)
	cases := []struct {
		name        string
		method      string
		path        string
		key         string
		challenge   string
		wantStatus  int
		wantProof   bool
		wantAllow   string
		wantNoStore bool
	}{
		{"valid proof", http.MethodGet, KeyProofPath, "test-key", valid, http.StatusOK, true, "", true},
		{"missing challenge", http.MethodGet, KeyProofPath, "test-key", "", http.StatusBadRequest, false, "", true},
		{"invalid challenge", http.MethodGet, KeyProofPath, "test-key", "not-base64!!", http.StatusBadRequest, false, "", true},
		{"wrong method", http.MethodPost, KeyProofPath, "test-key", valid, http.StatusMethodNotAllowed, false, http.MethodGet, true},
		{"wrong path", http.MethodGet, KeyProofPath + "/extra", "test-key", valid, http.StatusNotFound, false, "", true},
		{"no key", http.MethodGet, KeyProofPath, "", valid, http.StatusServiceUnavailable, false, "", true},
		{"no key and no challenge still 503", http.MethodGet, KeyProofPath, "", "", http.StatusServiceUnavailable, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.challenge != "" {
				req.Header.Set(testChallengeHeader, tc.challenge)
			}
			rec := httptest.NewRecorder()
			rec.Header().Set(testProofHeader, "stale-proof")
			ServeKeyProof(rec, req, tc.key)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			got := rec.Header().Get(testProofHeader)
			if tc.wantProof {
				if got == "" {
					t.Fatalf("proof header unset, want set")
				}
				if want := expectedProof(tc.key, tc.challenge); got != want {
					t.Fatalf("proof = %q, want %q", got, want)
				}
			} else if got != "" {
				t.Fatalf("proof = %q, want unset", got)
			}
			if tc.wantAllow != "" && rec.Header().Get("Allow") != tc.wantAllow {
				t.Fatalf("Allow = %q, want %q", rec.Header().Get("Allow"), tc.wantAllow)
			}
			if tc.wantNoStore && rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
		})
	}
}
