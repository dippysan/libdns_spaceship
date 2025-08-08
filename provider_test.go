package spaceship

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var provider = &Provider{
	APIKey:    os.Getenv("SPACESHIP_API_KEY"),
	APISecret: os.Getenv("SPACESHIP_API_SECRET"),
}

var (
	zone = os.Getenv("SPACESHIP_ZONE")
)

func TestAppendRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.RR{Name: "test-append", TTL: 10 * time.Minute, Type: "A", Data: "1.1.1.1"},
		libdns.TXT{Name: "test-append-txt", TTL: 10 * time.Minute, Text: "test append record"},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	fmt.Println("AppendRecords:", recs)
}

func TestSetRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.SetRecords(context.Background(), zone, []libdns.Record{
		libdns.RR{Name: "test-set", TTL: 10 * time.Minute, Type: "A", Data: "1.1.1.2"},
		libdns.TXT{Name: "test-set-txt", TTL: 10 * time.Minute, Text: "test set record"},
		libdns.CNAME{Name: "test-set-cname", TTL: 10 * time.Minute, Target: "example.com"},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	fmt.Println("SetRecords:", recs)
}

func TestGetRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	fmt.Println("GetRecords:", recs)
}

func TestDeleteRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.DeleteRecords(context.Background(), zone, []libdns.Record{
		libdns.RR{Name: "test-append", TTL: 10 * time.Minute, Type: "A", Data: "1.1.1.1"},
		libdns.TXT{Name: "test-append-txt", TTL: 10 * time.Minute, Text: "test append record"},
		libdns.RR{Name: "test-set", TTL: 10 * time.Minute, Type: "A", Data: "1.1.1.2"},
		libdns.TXT{Name: "test-set-txt", TTL: 10 * time.Minute, Text: "test set record"},
		libdns.CNAME{Name: "test-set-cname", TTL: 10 * time.Minute, Target: "example.com"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	fmt.Println("DeleteRecords:", recs)
}

func TestMXRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.MX{Name: "test-mx", TTL: 10 * time.Minute, Preference: 10, Target: "mail.example.com"},
	})
	if err != nil {
		t.Fatalf("AppendRecords MX: %v", err)
	}
	fmt.Println("AppendRecords MX:", recs)

	// Clean up
	_, err = provider.DeleteRecords(context.Background(), zone, []libdns.Record{
		libdns.MX{Name: "test-mx", TTL: 10 * time.Minute, Preference: 10, Target: "mail.example.com"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords MX: %v", err)
	}
}

func TestSRVRecords(t *testing.T) {
	if zone == "" {
		t.Skip("SPACESHIP_ZONE environment variable not set")
	}

	recs, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.SRV{Name: "test-srv", TTL: 10 * time.Minute, Priority: 10, Weight: 5, Port: 8080, Target: "srv.example.com"},
	})
	if err != nil {
		t.Fatalf("AppendRecords SRV: %v", err)
	}
	fmt.Println("AppendRecords SRV:", recs)

	// Clean up
	_, err = provider.DeleteRecords(context.Background(), zone, []libdns.Record{
		libdns.SRV{Name: "test-srv", TTL: 10 * time.Minute, Priority: 10, Weight: 5, Port: 8080, Target: "srv.example.com"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords SRV: %v", err)
	}
}
