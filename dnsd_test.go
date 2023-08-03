package dnsd

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	// Cloudflare Integration
	// If token, record, and zone are provided, the test is enabled.
	// The optional ipv4 flag indicates a static IP to use to update rather
	// than the default of using the defaultReporter.
	token  = flag.String("token", "", "Cloudflare token.")
	record = flag.String("record", "", "DNS record to update for test")
	zone   = flag.String("zone", "", "Zone in which record exists")
	ipv4   = flag.String("ipv4", "", "IPv4 addresss to update the record with")

	// Reporter Integration
	// Enables TestDefaultReporter which
)

// TestIntegration ensures that the integration between dnsd and the
// CloudFlare API is functional.  This test is not enabled by default.  To
// enable it, provide the flags -token, -zone and -record.
//
// -token is a Cloudflare token with permission to modify the -zone, and
// the -record being the fully-qualified-domain name record to update:
//
//	go test -v -token=$TOKEN -zone=example.com -record=dnsdtest.example.com
func TestCloudflare(t *testing.T) {
	// Skip the test unless required flags are provided
	if *token == "" || *record == "" || *zone == "" {
		t.Log("Cloudflare integration test not enabled.  Provide -token, -record and -zone to enable.")
		t.Skip()
	}

	// Create they syncer
	s := &Syncer{Zone: *zone, Record: *record, Token: *token}

	// Override with a static IP if flags provided
	if *ipv4 != "" {
		s.Reporter = func() (string, string, error) { return *ipv4, "", nil }
	}

	// Sync
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for at least one update to complete
	s.UpdateCh = make(chan error, 1)
	select {
	case <-time.After(30 * time.Second):
		t.Fatal("Test timed out.  No update in 10 seconds")
	case err := <-s.UpdateCh:
		if err != nil {
			t.Fatal(err)
		}
	}

}

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

	// Confirm both ID dereference requests received
	if !mockAPI.receivedZoneQuery {
		t.Fatal("Zone query not received")
	}
	if !mockAPI.receivedRecordQuery {
		t.Fatal("Record query not received")
	}
	if !mockAPI.receivedIPv4Put {
		t.Fatal("IPv4 put request not received")
	}
	if !mockAPI.receivedIPv6Put {
		t.Fatal("IPv6 put request not received")
	}
}

// put request as defined by the DNS Update API Documentation:
// https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record
type put struct {
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

	receivedZoneQuery   bool
	receivedRecordQuery bool
	receivedIPv4Put     bool
	receivedIPv6Put     bool
}

func (a *mockAPI) validateIPv4Put(p put) (err error) {
	ip, _, _ := a.s.Reporter()
	expected := put{
		Type:    "A",
		Content: ip,
		Name:    a.s.Record,
		TTL:     int(a.s.TTL.Seconds()),
	}
	if !reflect.DeepEqual(p, expected) {
		a.t.Fatalf("expected:\n%v\ngot:\n%v\n", format(expected), p)
	}
	a.receivedIPv4Put = true
	return
}

func (a *mockAPI) validateIPv6Put(p put) (err error) {
	_, ip, _ := a.s.Reporter()
	expected := put{
		Type:    "AAAA",
		Content: ip,
		Name:    a.s.Record,
		TTL:     int(a.s.TTL.Seconds()),
	}
	if !reflect.DeepEqual(p, expected) {
		a.t.Fatalf("expected:\n%v\ngot:\n%v\n", format(expected), p)
	}
	a.receivedIPv6Put = true
	return
}

func (a *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type Result struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	type Response struct {
		Success bool     `json:"success"`
		Result  []Result `json:"result"`
	}
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
		if strings.HasSuffix(r.RequestURI, "/zones/?name="+a.s.Zone) {
			a.receivedZoneQuery = true
			// Send back a zone ID which will be expected to be received later
			err := json.NewEncoder(w).Encode(Response{Success: true, Result: []Result{{ID: "zoneid"}}})
			if err != nil {
				a.t.Fatal(err)
			}
		} else if strings.HasSuffix(r.RequestURI, "/zones/zoneid/dns_records/?name="+a.s.Record) {
			a.receivedRecordQuery = true
			// Send back a zone ID which will be expected to be received later
			err := json.NewEncoder(w).Encode(Response{Success: true, Result: []Result{{ID: "recordid", Type: "A"}}})
			if err != nil {
				a.t.Fatal(err)
			}
		} else {
			a.t.Fatalf("unexpected GET request received: %v", r.RequestURI)
		}

	} else if r.Method == "PUT" {
		var p put
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			a.t.Fatal(err)
		}
		defer r.Body.Close()

		// One GET request should be for the A record
		if p.Type == "A" {
			if err := a.validateIPv4Put(p); err != nil {
				a.t.Fatal(err)
			}
		} else if p.Type == "AAAA" {
			// The other PUT for AAAA
			if err := a.validateIPv6Put(p); err != nil {
				a.t.Fatal(err)
			}
		} else {
			a.t.Fatalf("unexpected type received: %v", p.Type)
		}
	} else {
		// Any other request methods are errors.
		a.t.Fatalf("expected 'PUT', got '%s'", r.Method)
	}
	if err := json.NewEncoder(w).Encode(Response{Success: true}); err != nil {
		a.t.Fatal(err)
	}
}

func format(p put) string {
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

	ipv4Str, _, err := defaultReporter()
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
	// TODO
	/*
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
	*/

}
