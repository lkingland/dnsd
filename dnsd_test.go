package dnsd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestSync ensures that the syncer is functioning as intended.
// This is a Unit test which uses mocks for the Cloudflare API and the
// Public IP reporter.  Therefore those aspects of the system are not
// validated herein.
func TestSync(t *testing.T) {

	// A single Syncer instances maintains the public IP address of a single
	// domain, IPv4 and IPv6, by updating the A and AAAA records of the given
	// domain.
	s := &Syncer{Zone: "example.com", Record: "www.example.com", Token: "TEST_TOKEN"}

	// Override the Syncer's default IP reporter, which looks up the
	// current public IP address, with a mock implementation.
	s.Reporter = mockReporter

	// MockAPI receives requests and verifies they are what the CloudFlare API
	// woudld expect to receive given the current state of the syncer.
	mockAPI := &mockAPI{s: s, t: t}
	ts := httptest.NewServer(mockAPI)
	defer ts.Close()
	s.Endpoint = ts.URL

	// Register a channel with the syncer to be notified whenever an update
	// is attempted and any errors generated.
	s.UpdateCh = make(chan error, 1)

	// Start the syncer
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for an update
	if err := <-s.UpdateCh; err != nil {
		t.Fatal(err)
	}

	// The handler will have failed the test if it received an invalid request.

	// Confirm both patches received
	if !mockAPI.receivedZoneQuery {
		t.Fatal("Zone query not received")
	}
	if !mockAPI.receivedIPv4Patch {
		t.Fatal("IPv4 patch request not received")
	}
	if !mockAPI.receivedIPv6Patch {
		t.Fatal("IPv6 patch request not received")
	}
}

// patch request as defined by the DNS Update API Documentation:
// https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record
type patch struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// mockReporter which returns hard-coded addresses.
func mockReporter() (ipv4, ipv6 string, err error) {
	return "192.0.2.1", "2001:db8::1", nil
}

// mockAPI which will validate that requests received are one of the two
// expected, and records that both were received.
type mockAPI struct {
	s *Syncer
	t *testing.T

	receivedZoneQuery bool
	receivedIPv4Patch bool
	receivedIPv6Patch bool
}

func (a *mockAPI) validateZoneQuery(r *http.Request) (err error) {
	if strings.HasSuffix(r.RequestURI, "/zones/?name="+a.s.Zone) {
		a.receivedZoneQuery = true
	} else {
		return fmt.Errorf("unexpected zone query received: %v", r.RequestURI)
	}
	return
}

func (a *mockAPI) validateIPv4Patch(p patch) (err error) {
	ip, _, _ := a.s.Reporter()
	expected := patch{
		Type:    "A",
		Content: ip,
		Name:    a.s.Record,
		TTL:     int(a.s.TTL.Seconds()),
	}
	if !reflect.DeepEqual(p, expected) {
		a.t.Fatalf("expected:\n%v\ngot:\n%v\n", format(expected), p)
	}
	a.receivedIPv4Patch = true
	return
}

func (a *mockAPI) validateIPv6Patch(p patch) (err error) {
	_, ip, _ := a.s.Reporter()
	expected := patch{
		Type:    "AAAA",
		Content: ip,
		Name:    a.s.Record,
		TTL:     int(a.s.TTL.Seconds()),
	}
	if !reflect.DeepEqual(p, expected) {
		a.t.Fatalf("expected:\n%v\ngot:\n%v\n", format(expected), p)
	}
	a.receivedIPv6Patch = true
	return
}

func (a *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// All requests must be JSON
	if r.Header.Get("Content-Type") != "application/json" {
		a.t.Fatal("all requests must have the header Content-Type=application/json")
	}
	// All requests must include the bearer token
	if r.Header.Get("Authorization") != "Bearer "+a.s.Token {
		a.t.Fatalf("Request %q does not include the bearer token. expectd %q got %q",
			r.RequestURI, "Bearer "+a.s.Token, r.Header.Get("Authorization"))
	}
	if r.Method == "GET" {
		// The only GET request should be to lookup the zone ID
		if err := a.validateZoneQuery(r); err != nil {
			a.t.Fatal(err)
		}
		// Send back a zone ID which will be expected to be received later
		type Result struct {
			ID string `json:"id"`
		}
		type Response struct {
			Result []Result `json:"result"`
		}
		err := json.NewEncoder(w).Encode(Response{[]Result{{"id"}}})
		if err != nil {
			a.t.Fatal(err)
		}
	} else if r.Method == "PATCH" {
		var p patch
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			a.t.Fatal(err)
		}
		defer r.Body.Close()

		// One PATCH request should be for the A record
		if p.Type == "A" {
			if err := a.validateIPv4Patch(p); err != nil {
				a.t.Fatal(err)
			}
		} else if p.Type == "AAAA" {
			// The other PATCH for AAAA
			if err := a.validateIPv6Patch(p); err != nil {
				a.t.Fatal(err)
			}
		} else {
			a.t.Fatalf("unexpected type received: %v", p.Type)
		}
	} else {
		// Any other request methods are errors.
		a.t.Fatalf("expected 'PATCH', got '%s'", r.Method)
	}
}

func format(p patch) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	_ = enc.Encode(p)
	return b.String()
}

func (a *mockAPI) Start() (url string) {
	ts := httptest.NewServer(a)
	return ts.URL
}

// TestDefaultReporter ensures that the default reporter, which
// makes a public IP lookup request, returns with valid IP addresses.
// Validating the IPs are actually correct is outside the scope of this unit.
func TestDefaultReporter(t *testing.T) {
	// Temporarily disabled as this is not reliable when used on a development
	// box with a VPN running.  TODO: perhaps place this test
	// behind a flag, and run it in CI only as a PR acceptance criteria.
	t.Log("test disabled")
	return

	ipv4Str, ipv6Str, err := defaultReporter()
	if err != nil {
		t.Fatal(err)
	}

	// Validate IPv4 address
	t.Logf("ipv4Str: %v", ipv4Str)
	if ipv4Str == "" {
		t.Fatal("ipv4 address not found")
	}
	ipv4 := net.ParseIP(ipv4Str)
	if ipv4 == nil {
		t.Fatalf("ipv4 address %q not parseable", ipv4Str)
	}
	if ipv4.To4() == nil {
		t.Fatalf("ipv4 address %q not parseable as an IPv4 address", ipv4Str)
	}

	// Validate IPv6 address
	t.Logf("ipv6Str: %v", ipv6Str)
	if ipv6Str == "" {
		t.Fatal("ipv6 address not found")
	}
	ipv6 := net.ParseIP(ipv6Str)
	if ipv6 == nil {
		t.Fatalf("ipv6 address %q not parseable", ipv6Str)
	}
	if ipv6.To16() == nil {
		t.Fatalf("ipv6 address %q not parseable as an IPv6 address", ipv6Str)
	}

}
