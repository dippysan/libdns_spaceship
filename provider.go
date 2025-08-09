// Package spaceship implements a DNS record management client compatible
// with the libdns interfaces for Spaceship.
package spaceship

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Spaceship.
type Provider struct {
	APIKey    string
	APISecret string
	client    *SpaceshipClient
	once      sync.Once
	mutex     sync.Mutex
}

// init initializes the provider.
func (p *Provider) init(ctx context.Context) {
	p.once.Do(func() {
		p.client = NewSpaceshipClient(p.APIKey, p.APISecret)
	})
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	records, err := p.client.GetRecords(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records for zone %s: %w", zone, err)
	}

	var libdnsRecords []libdns.Record
	for _, rec := range records {
		record := p.convertToLibdnsRecord(rec, zone)
		if record != nil {
			libdnsRecords = append(libdnsRecords, record)
		}
	}

	return libdnsRecords, nil
}

// convertToLibdnsRecord converts a Spaceship record to a libdns record type
func (p *Provider) convertToLibdnsRecord(rec SpaceshipRecord, zone string) libdns.Record {
	// Remove trailing dot if present, but don't remove the last character if it's not a dot
	name := rec.Name
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	relName := libdns.RelativeName(name, zone)
	ttl := time.Duration(rec.TTL) * time.Second

	switch strings.ToUpper(rec.Type) {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			// Fallback to RR for invalid IP
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		return libdns.Address{
			Name: relName,
			TTL:  ttl,
			IP:   ip,
		}
	case "MX":
		// Handle MX record with Exchange field
		target := rec.Value
		if rec.Exchange != "" {
			target = rec.Exchange
		} else {
			// Fallback to parsing from Value field
			parts := strings.Fields(rec.Value)
			if len(parts) != 2 {
				// Fallback to RR for invalid MX data
				return libdns.RR{
					Name: relName,
					Type: rec.Type,
					Data: rec.Value,
					TTL:  ttl,
				}
			}
			target = parts[1]
		}

		pref, err := strconv.ParseUint(rec.Value, 10, 16)
		if err != nil {
			// Fallback to RR for invalid preference
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		return libdns.MX{
			Name:       relName,
			TTL:        ttl,
			Preference: uint16(pref),
			Target:     target,
		}
	case "TXT":
		return libdns.TXT{
			Name: relName,
			TTL:  ttl,
			Text: rec.Value,
		}
	case "CNAME":
		target := rec.Value
		if rec.Cname != "" {
			target = rec.Cname
		}
		return libdns.CNAME{
			Name:   relName,
			TTL:    ttl,
			Target: target,
		}
	case "NS":
		return libdns.NS{
			Name:   relName,
			TTL:    ttl,
			Target: rec.Value,
		}
	case "SRV":
		// Parse SRV record data: "priority weight port target"
		parts := strings.Fields(rec.Value)
		if len(parts) != 4 {
			// Fallback to RR for invalid SRV data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		priority, err1 := strconv.ParseUint(parts[0], 10, 16)
		weight, err2 := strconv.ParseUint(parts[1], 10, 16)
		port, err3 := strconv.ParseUint(parts[2], 10, 16)
		if err1 != nil || err2 != nil || err3 != nil {
			// Fallback to RR for invalid SRV data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		return libdns.SRV{
			Name:     relName,
			TTL:      ttl,
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   parts[3],
		}
	case "CAA":
		// Parse CAA record data: "flags tag value"
		parts := strings.SplitN(rec.Value, " ", 3)
		if len(parts) != 3 {
			// Fallback to RR for invalid CAA data
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		flags, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			// Fallback to RR for invalid flags
			return libdns.RR{
				Name: relName,
				Type: rec.Type,
				Data: rec.Value,
				TTL:  ttl,
			}
		}
		return libdns.CAA{
			Name:  relName,
			TTL:   ttl,
			Flags: uint8(flags),
			Tag:   parts[1],
			Value: parts[2],
		}
	default:
		// Fallback to RR for unsupported record types
		return libdns.RR{
			Name: relName,
			Type: rec.Type,
			Data: rec.Value,
			TTL:  ttl,
		}
	}
}

// convertFromLibdnsRecord converts a libdns record to Spaceship record
func (p *Provider) convertFromLibdnsRecord(record libdns.Record, zone string) SpaceshipRecord {
	rr := record.RR()

	rec := SpaceshipRecord{
		Type: rr.Type,
		Name: p.fqdn(rr.Name, zone),
		TTL:  int(rr.TTL.Seconds()),
	}

	// Handle different record types
	switch typed := record.(type) {
	case libdns.Address:
		rec.Value = typed.IP.String()
	case libdns.CNAME:
		rec.Cname = typed.Target
	case libdns.NS:
		rec.Value = typed.Target
	case libdns.TXT:
		rec.Value = typed.Text
	case libdns.MX:
		rec.Exchange = typed.Target
		rec.Value = fmt.Sprintf("%d", typed.Preference)
	case libdns.SRV:
		rec.Value = fmt.Sprintf("%d %d %d %s", typed.Priority, typed.Weight, typed.Port, typed.Target)
	case libdns.CAA:
		rec.Value = fmt.Sprintf("%d %s %s", typed.Flags, typed.Tag, typed.Value)
	default:
		rec.Value = rr.Data
	}

	return rec
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var createdRecords []libdns.Record
	for _, record := range records {
		rec := p.convertFromLibdnsRecord(record, zone)

		err := p.client.CreateRecord(zone, rec)
		if err != nil {
			rr := record.RR()
			return nil, fmt.Errorf("failed to create record %s: zone %s, record %+v, rec %+v, error %w", rr.Name, zone, record, rec, err)
		}

		createdRecords = append(createdRecords, record)
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var updatedRecords []libdns.Record

	for _, record := range records {
		// Attempt to update the record using the client
		updateRec, err := p.upsertRecord(record, zone)
		if err != nil {
			rr := record.RR()
			return nil, fmt.Errorf("failed to update record %s: zone %s, record %+v, updateRec %+v, error %w", rr.Name, zone, record, updateRec, err)
		}

		// Convert updated SpaceshipRecord to libdns.Record and append to the result slice
		updatedRecord := p.convertToLibdnsRecord(*updateRec, zone)
		if updatedRecord != nil {
			updatedRecords = append(updatedRecords, updatedRecord)
		}
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	all_records, err := p.client.GetRecords(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records for zone %s: error %w", zone, err)
	}

	var deletedRecords []libdns.Record

	for _, record := range records {
		rr := record.RR()

		// Find the record to delete
		found := false
		for _, rec := range all_records {
			if p.fqdn(rec.Name, zone) == p.fqdn(rr.Name, zone) && rec.Type == rr.Type {
				err := p.client.DeleteRecord(zone, rec)
				if err != nil {
					return nil, fmt.Errorf("failed to delete record %s: zone %s, record %+v, rec %+v, error %w", rr.Name, zone, record, rec, err)
				}
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("record %s of type %s not found", rr.Name, rr.Type)
		}

		deletedRecords = append(deletedRecords, record)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
