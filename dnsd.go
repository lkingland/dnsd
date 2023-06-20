package dnsd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// DefaultEndpoint where the CloudFlare API can be reached.
	DefaultEndpoint = "https://api.cloudflare.com/client/v4"

	// DefaultTTL for all DNS record updates.
	DefaultTTL = 3600 * time.Second

	// DefaultResolution is to check for update.
	DefaultResolution = 10 * time.Minute

	// DefaultLogLevel for the package.  Use SetLogLevel to change.
	DefaultLogLevel = LogDebug
)

// Syncer of a single DNS domain's A and AAAA records.
type Syncer struct {
	Endpoint   string        // API endpoint (default is DefaultEndpoint)
	Zone       string        // Zone. eg example.com
	Record     string        // Record to update. eg www.example.com
	Token      string        // Token for accessing the remote API
	TTL        time.Duration // TTL to set for DNS records on update
	Resolution time.Duration // How often to check for changes
	UpdateCh   chan error    // Channel to notify of each update with any errors
	Reporter   Reporter      // Reporter of current routable IPs

	// Cache
	lastipv4 string
	lastipv6 string
	zoneID   string
	recordID string
}

func (s *Syncer) Start(ctx context.Context) error {
	// Preconditions
	if s.Token == "" {
		return errors.New("dnsd syncer requires a token")
	}
	if s.Record == "" {
		return errors.New("dnsd syncer requires a record name to sync")
	}

	// Defaults
	if s.TTL == time.Duration(0) {
		s.TTL = DefaultTTL
	}
	if s.Reporter == nil {
		s.Reporter = defaultReporter
	}
	if s.Endpoint == "" {
		s.Endpoint = DefaultEndpoint
	}
	if s.Resolution == time.Duration(0) {
		s.Resolution = DefaultResolution
	}

	// In a separate goroutine, syncrhonize at the given resolution, notifying
	// the update channel with either a nil or any errors encountered during
	// the sync.  Run forever unless the context is canceled, in which case
	// the message sent to the update channel is the context error or nil.
	// If no update channel is defined, simply print any errors to log.
	go func() {
		for {
			// Sync, notifying when complete, with the error (if any)
			s.onUpdate(s.sync())

			// Wait for either a context cancellation or for the resolution
			// timeout.  Context cancellation reports on the update channel
			// (with nil or error).  The resolution ticker releases the loop
			// to the next iteration.

			select {
			case <-ctx.Done():
				log.Info().Msg("syncer canceled")
				s.onUpdate(ctx.Err())
			case <-time.After(s.Resolution):
				// continue
			}
		}
	}()
	return nil
}

func (s *Syncer) sync() (err error) {
	// Get the current IP addresses
	ipv4, ipv6, err := s.Reporter()
	if err != nil {
		return
	}
	log.Debug().Str("ipv4", ipv4).Str("ipv6", ipv6).Msg("resolved ips")

	// Return if they have not changed.
	if ipv4 == s.lastipv4 && ipv6 != s.lastipv6 {
		log.Debug().Msg("dnsd addresses are current")
		return nil
	}

	// log we're commencing update
	log.Info().
		Str("zone", s.Zone).
		Str("record", s.Record).
		Str("ipv4", ipv4).
		Str("ipv6", ipv6).
		Int("ttl", int(s.TTL.Seconds())).
		Msg("syncing")

	// Update the ipv4 address
	if err = s.put("A", ipv4); err != nil {
		return
	}

	// Update the ipv6 address if found
	if ipv6 != "" {
		if err = s.put("AAAA", ipv6); err != nil {
			return
		}
	}

	log.Info().Msg("sync complete")
	return
}

// put a record (A|AAAA) with value (IPv4 or IPv6 address, respectively)
func (s *Syncer) put(key, value string) (err error) {
	// API Endpoint
	zoneID, err := s.ZoneID()
	if err != nil {
		return
	}
	recordID, err := s.RecordID()
	if err != nil {
		return
	}
	log.Debug().Str("zone", zoneID).Str("record", recordID).Msg("ids retreived")

	endpoint := s.Endpoint + "/zones/" + zoneID + "/dns_records/" + recordID

	// Request Object
	request := updateRequest{
		Type:    key,
		Content: value,
		Name:    s.Record,
		TTL:     int(s.TTL.Seconds()),
	}

	// PUT
	var body bytes.Buffer
	if err = json.NewEncoder(&body).Encode(request); err != nil {
		return
	}
	req, err := http.NewRequest("PUT", endpoint, &body)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.Token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	r := response{}
	if err = json.NewDecoder(res.Body).Decode(&r); err != nil {
		return
	}
	if !r.Success {
		return ErrRemote{Endpoint: endpoint, Errors: r.Errors}
	}

	// TODO: parse the rsponse for 200 OK (request) but errors?

	return
}

func (s *Syncer) zones() []string {
	url := s.Endpoint + "/zones"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []string{}
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.Token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return []string{}
	}
	r := struct {
		Result []struct {
			Name string `json:"name"`
		} `json:"result"`
	}{}
	if err = json.NewDecoder(res.Body).Decode(&r); err != nil {
		return []string{}
	}
	names := []string{}
	for _, result := range r.Result {
		names = append(names, result.Name)
	}
	return names
}

func (s *Syncer) records() []string {
	zoneID, err := s.ZoneID()
	if err != nil {
		return []string{}
	}
	url := s.Endpoint + "/zones/" + zoneID + "/dns_records"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []string{}
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.Token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return []string{}
	}
	r := struct {
		Result []struct {
			Name string `json:"name"`
		} `json:"result"`
	}{}
	if err = json.NewDecoder(res.Body).Decode(&r); err != nil {
		return []string{}
	}
	names := []string{}
	for _, result := range r.Result {
		names = append(names, result.Name)
	}
	return names
}

// ZoneID returns the ID for the current Syncer's named Zone
func (s *Syncer) ZoneID() (id string, err error) {
	if s.zoneID != "" {
		return s.zoneID, nil // Cache
	}

	// Build the lookup request
	endpoint := s.Endpoint + "/zones/?name=" + s.Zone
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.Token)

	// Issue the Lookup Request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	r := zoneResponse{}
	if err = json.NewDecoder(res.Body).Decode(&r); err != nil {
		return
	}
	if !r.Success {
		return "", ErrRemote{Endpoint: endpoint, Errors: r.Errors}
	}

	// Evaluate the Response
	if len(r.Result) == 0 {
		return "", ErrZoneNotFound{
			Zone:  s.Zone,
			Zones: s.zones(),
		}
	} else if len(r.Result) > 1 {
		return "", fmt.Errorf("zone ID lookup reutned %v results (expected 1)",
			len(r.Result))
	}

	s.zoneID = r.Result[0].ID
	return s.zoneID, nil
}

// RecordID returns the ID for the current Syncer's named Record
func (s *Syncer) RecordID() (id string, err error) {
	if s.recordID != "" {
		return s.recordID, nil // Cache
	}

	// Build the lookup request
	zoneID, err := s.ZoneID()
	if err != nil {
		return
	}
	url := s.Endpoint + "/zones/" + zoneID + "/dns_records/?name=" + s.Record
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.Token)

	// Issue the Lookup Request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	r := zoneResponse{}
	if err = json.NewDecoder(res.Body).Decode(&r); err != nil {
		return
	}
	if !r.Success {
		return "", ErrRemote{Errors: r.Errors}
	}

	// Evaluate the Response
	if len(r.Result) == 0 {
		return "", ErrRecordNotFound{
			Zone:    s.Zone,
			Record:  s.Record,
			Records: s.records(),
		}
	} else if len(r.Result) > 1 {
		return "", fmt.Errorf("record lookup returned %v results (expected 1)",
			len(r.Result))
	}

	s.recordID = r.Result[0].ID
	return s.recordID, nil
}

func (s *Syncer) onUpdate(err error) {
	// If there is an udpate channel, send nil or the error.
	if s.UpdateCh != nil {
		s.UpdateCh <- err
	}
	// Print to log
	if err != nil {
		log.Error().Err(err).Msg("sync error")
	}
}

// Reporter of IP addresses
type Reporter func() (ipv4, ipv6 string, err error)

// defaultReporter uses ipify.org and ipecho.net
var defaultReporter = func() (ipv4, ipv6 string, err error) {
	// TODO: contact another instance of dnsd by default, fallig
	// back to ipify, ipecho, etc.
	// When using the fallback, run each concurrently witha  fairly short
	// timeout. If both come back, compare, but if not just log a notice that
	// we were unable to do a validation.

	// ipify.org
	// ---------
	res, err := http.Get("https://api.ipify.org")
	if err != nil {
		return
	}
	defer res.Body.Close()

	bb, err := io.ReadAll(res.Body)
	if err != nil {
		return
	}
	ipv4 = string(bb)

	// ipecho.net
	// ---------
	res, err = http.Get("https://ipecho.net/plain")
	if err != nil {
		return
	}
	bb, err = io.ReadAll(res.Body)
	if err != nil {
		return
	}
	ipv4B := string(bb)

	// Cross-check
	// -----------
	if ipv4 != ipv4B {
		log.Error().Str("ipify.org", ipv4).Str("ipecho.net", ipv4B).Msg("mismatch in ipv4 reported by third-parties.")
		err = fmt.Errorf("received to differing ipv4 addresses. %v and %v", ipv4, ipv4B)
		return
	}

	// TODO: IPv6 address only works when it is the exact server on which
	// the load-balancer for the cluster is running.  Therefore the following
	// implementation should only be actively used when running as a sampling
	// service, and the actual dnsd service should be configured to reach
	// out to the load-balancer, asking for its IPv6 address.
	var inSamplerMode = false
	if inSamplerMode {
		// Get our public IPv6 from ipify.org
		res, err = http.Get("https://api64.ipify.org")
		if err != nil {
			return
		}
		defer res.Body.Close()

		bb, err = io.ReadAll(res.Body)
		if err != nil {
			return
		}
		ipv6 = string(bb)

		// Confirm it is the current machine
		var ipv6ok bool
		for _, addr := range addresses() {
			addr = strings.TrimSuffix(addr, "/64") // trim netmask
			if ipv6 == addr {
				ipv6ok = true
				break
			}
		}
		if !ipv6ok {
			return "", "", fmt.Errorf("reported ipv6 address %q not present locally", ipv6)
		}

	}

	log.Debug().Str("ipv4", ipv4).Str("ipv6", ipv6).Msg("addresses found")

	return
}

func addresses() (ips []string) {
	ips = []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Error().Err(err).Msg("unable to list available interfaces")
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Error().Err(err).Msg("unable to list addresses for interface")
			return
		}
		for _, addr := range addrs {
			log.Info().Str("addr", addr.String()).Str("name", iface.Name).Msg("interface found")
			ips = append(ips, addr.String())
		}
	}
	return
}

// Requests
// --------

type updateRequest struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	Name    string `json:"name"`
	TTL     int    `json:"ttl"`
}

// Responses
// ---------

type response struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type zoneResponse struct {
	response
	Result []struct {
		ID string `json:"id"`
	} `json:"result"`
}

// Errors
// ------

type ErrRemote struct {
	Endpoint string
	Errors   []struct {
		Message string `json:"message"`
	}
}

func (e ErrRemote) Error() string {
	s := strings.Builder{}
	s.WriteString(fmt.Sprintf("endpoint %q returned errors:", e.Endpoint))
	ee := []string{}
	for _, e := range e.Errors {
		ee = append(ee, e.Message)
	}
	s.WriteString(strings.Join(ee, ". "))
	return s.String()
}

type ErrZoneNotFound struct {
	Zone  string
	Zones []string
}

func (e ErrZoneNotFound) Error() string {
	s := strings.Builder{}
	s.WriteString("zone not found: ")
	s.WriteString(e.Zone)
	s.WriteString(".  Available zones:")
	for _, z := range e.Zones {
		s.WriteString("\n  " + z)
	}
	return s.String()
}

type ErrRecordNotFound struct {
	Zone    string
	Record  string
	Records []string
}

func (e ErrRecordNotFound) Error() string {
	s := strings.Builder{}
	s.WriteString(fmt.Sprintf("record %v not found for zone %v.  Available records: ",
		e.Record, e.Zone))
	for _, z := range e.Records {
		s.WriteString("\n  " + z)
	}
	return s.String()
}
