package spaceship

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// SpaceshipClient represents a client for the Spaceship DNS API
type SpaceshipClient struct {
	apiKey    string
	apiSecret string
	client    *http.Client
	baseURL   string
}

// SpaceshipRecord represents a DNS record in the Spaceship API format
type SpaceshipRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Cname    string `json:"cname,omitempty"`
	Exchange string `json:"exchange,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

// SpaceshipRecordsResponse represents the response from the Spaceship API
type SpaceshipRecordsResponse struct {
	Items []SpaceshipRecord `json:"items"`
	Total int               `json:"total"`
}

// NewSpaceshipClient creates a new Spaceship API client
func NewSpaceshipClient(apiKey, apiSecret string) *SpaceshipClient {
	return &SpaceshipClient{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		client:    &http.Client{Timeout: 30 * time.Second},
		baseURL:   "https://spaceship.dev/api/v1",
	}
}

// GetRecords retrieves DNS records for a domain
func (c *SpaceshipClient) GetRecords(domain string) ([]SpaceshipRecord, error) {
	// Remove trailing dot for API compatibility
	domain = strings.TrimSuffix(domain, ".")
	url := fmt.Sprintf("%s/dns/records/%s?take=500&skip=0", c.baseURL, domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-API-Secret", c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	var response SpaceshipRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Items, nil
}

// CreateRecord creates a new DNS record
func (c *SpaceshipClient) CreateRecord(domain string, record SpaceshipRecord) error {
	// Remove trailing dot for API compatibility
	domain = strings.TrimSuffix(domain, ".")
	url := fmt.Sprintf("%s/dns/records/%s", c.baseURL, domain)

	// API expects an object with "items" field containing the record
	requestBody := struct {
		Items []SpaceshipRecord `json:"items"`
	}{
		Items: []SpaceshipRecord{record},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-API-Secret", c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		// Try to read error response body
		var errorBody []byte
		if resp.Body != nil {
			errorBody, _ = io.ReadAll(resp.Body)
		}
		return fmt.Errorf("CreateRecord API request for domain %s and record %+v failed with status: %d, body: %s", domain, record, resp.StatusCode, string(errorBody))

	}

	return nil
}

// DeleteRecord deletes a DNS record
func (c *SpaceshipClient) DeleteRecord(domain string, record SpaceshipRecord) error {
	// Remove trailing dot for API compatibility
	domain = strings.TrimSuffix(domain, ".")
	url := fmt.Sprintf("%s/dns/records/%s", c.baseURL, domain)

	// Try sending just the array of records for DELETE
	body, err := json.Marshal([]SpaceshipRecord{record})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-API-Secret", c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		// Try to read error response body
		var errorBody []byte
		if resp.Body != nil {
			errorBody, _ = io.ReadAll(resp.Body)
		}
		return fmt.Errorf("DeleteRecord API request for domain %s and record %+v failed with status: %d, body: %s", domain, record, resp.StatusCode, string(errorBody))
	}

	return nil
}

// fqdn returns a fully qualified domain name.
func (p *Provider) fqdn(name, zone string) string {
	name = strings.TrimRight(name, ".")
	zone = strings.TrimRight(zone, ".")
	if !strings.HasSuffix(name, zone) {
		name += "." + zone
	}
	return name
}

// upsertRecord adds or updates records to the zone. It returns the records that were added or updated.
func (p *Provider) upsertRecord(record libdns.Record, zone string) (*SpaceshipRecord, error) {
	records, err := p.client.GetRecords(zone)
	if err != nil {
		return nil, err
	}

	rr := record.RR()

	update_rec := SpaceshipRecord{
		Type: rr.Type,
		Name: p.fqdn(rr.Name, zone),
		TTL:  int(rr.TTL.Seconds()),
	}

	// Handle different record types
	switch rec := record.(type) {
	case libdns.Address:
		update_rec.Value = rec.IP.String()
	case libdns.CNAME:
		update_rec.Cname = rec.Target
	case libdns.NS:
		update_rec.Value = rec.Target
	case libdns.TXT:
		update_rec.Value = rec.Text
	case libdns.MX:
		update_rec.Exchange = rec.Target
		update_rec.Value = fmt.Sprintf("%d", rec.Preference)
	case libdns.SRV:
		update_rec.Value = fmt.Sprintf("%d %d %d %s", rec.Priority, rec.Weight, rec.Port, rec.Target)
	case libdns.CAA:
		update_rec.Value = fmt.Sprintf("%d %s %s", rec.Flags, rec.Tag, rec.Value)
	default:
		update_rec.Value = rr.Data
	}

	// Check if record exists and update it
	for _, rec := range records {
		if p.fqdn(rec.Name, zone) == p.fqdn(rr.Name, zone) && rec.Type == rr.Type {
			// For Spaceship API, we need to delete and recreate for updates
			err := p.client.DeleteRecord(zone, rec)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	// Create the new record
	err = p.client.CreateRecord(zone, update_rec)
	if err != nil {
		return nil, err
	}

	return &update_rec, nil
}

// getPriority returns the priority of a record and 0 if it is nil.
func getPriority(prio *int) int {
	if prio != nil {
		return *prio
	}
	return 0
}
