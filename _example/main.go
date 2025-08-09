package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	spaceship "github.com/dippysan/libdns_spaceship"
	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Warning: Could not load .env file: %s\n", err.Error())
		// Continue execution as environment variables might be set directly
	}

	apiKey := os.Getenv("SPACESHIP_API_KEY")
	if apiKey == "" {
		fmt.Printf("SPACESHIP_API_KEY not set\n")
		return
	}

	apiSecret := os.Getenv("SPACESHIP_API_SECRET")
	if apiSecret == "" {
		fmt.Printf("SPACESHIP_API_SECRET not set\n")
		return
	}

	zone := os.Getenv("SPACESHIP_ZONE")
	if zone == "" {
		fmt.Printf("SPACESHIP_ZONE not set\n")
		return
	}

	provider := spaceship.Provider{
		APIKey:    apiKey,
		APISecret: apiSecret,
	}

	records, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("ERROR getting records: %s\n", err.Error())
		return
	}

	testName := "libdns-test"
	fmt.Printf("Found %d existing records in zone %s:\n", len(records), zone)

	for _, record := range records {
		fmt.Printf("  %s: %s, %s\n", record.RR().Name, record.RR().Type, record.RR().Data)
	}

	// Check if test record already exists
	testRecordExists := false
	for _, record := range records {
		if record.RR().Name == testName {
			testRecordExists = true
			break
		}
	}

	if testRecordExists {
		fmt.Printf("Replacing existing entry for %s\n", testName)
		_, err = provider.SetRecords(context.TODO(), zone, []libdns.Record{libdns.TXT{
			Name: testName,
			Text: fmt.Sprintf("Replacement test entry created by libdns %s", time.Now()),
			TTL:  time.Duration(300) * time.Second, // 5 minutes instead of 30 seconds
		}})
		if err != nil {
			fmt.Printf("ERROR setting record: %s\n", err.Error())
			return
		}
		fmt.Printf("Successfully updated test record\n")
	} else {
		fmt.Printf("Creating new entry for %s\n", testName)
		_, err = provider.AppendRecords(context.TODO(), zone, []libdns.Record{libdns.TXT{
			Name: testName,
			Text: fmt.Sprintf("This is a test entry created by libdns %s", time.Now()),
			TTL:  time.Duration(300) * time.Second, // 5 minutes instead of 30 seconds
		}})
		if err != nil {
			fmt.Printf("ERROR creating record: %s\n", err.Error())
			return
		}
		fmt.Printf("Successfully created test record\n")
	}

	// Verify the record was created/updated
	fmt.Printf("\nVerifying record...\n")
	updatedRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("ERROR getting updated records: %s\n", err.Error())
		return
	}

	for _, record := range updatedRecords {
		if record.RR().Name == testName {
			fmt.Printf("Found test record: %s: %s, %s\n", record.RR().Name, record.RR().Type, record.RR().Data)
			break
		}
	}

	// Demonstrate different record types and DeleteRecords functionality
	fmt.Printf("\nDemonstrating different record types and DeleteRecords functionality...\n")

	// Create different types of temporary records to demonstrate various record types
	tempRecords := []libdns.Record{
		libdns.TXT{
			Name: "temp-txt-test",
			Text: "Temporary TXT record for testing",
			TTL:  time.Duration(300) * time.Second,
		},
		libdns.CNAME{
			Name:   "temp-cname-test",
			Target: "example.com",
			TTL:    time.Duration(300) * time.Second,
		},
		libdns.MX{
			Name:       "temp-mx-test",
			Preference: 10,
			Target:     "mail.example.com",
			TTL:        time.Duration(300) * time.Second,
		},
	}

	fmt.Printf("Creating multiple temporary records for testing...\n")
	_, err = provider.AppendRecords(context.TODO(), zone, tempRecords)
	if err != nil {
		fmt.Printf("ERROR creating temporary records: %s\n", err.Error())
		return
	}
	fmt.Printf("Successfully created temporary records\n")

	// Verify the temporary records were created
	allRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("ERROR getting records for verification: %s\n", err.Error())
		return
	}

	// Count and display the temporary records
	tempRecordCount := 0
	for _, record := range allRecords {
		name := record.RR().Name
		if strings.HasPrefix(name, "temp-") {
			tempRecordCount++
			fmt.Printf("Found temporary record: %s: %s, %s\n", record.RR().Name, record.RR().Type, record.RR().Data)
		}
	}

	if tempRecordCount > 0 {
		fmt.Printf("Found %d temporary records\n", tempRecordCount)

		// Delete all temporary records
		fmt.Printf("Deleting all temporary records...\n")
		_, err = provider.DeleteRecords(context.TODO(), zone, tempRecords)
		if err != nil {
			fmt.Printf("ERROR deleting temporary records: %s\n", err.Error())
			return
		}
		fmt.Printf("Successfully deleted temporary records\n")

		// Verify the temporary records were deleted
		finalRecords, err := provider.GetRecords(context.TODO(), zone)
		if err != nil {
			fmt.Printf("ERROR getting final records: %s\n", err.Error())
			return
		}

		remainingTempRecords := 0
		for _, record := range finalRecords {
			name := record.RR().Name
			if strings.HasPrefix(name, "temp-") {
				remainingTempRecords++
			}
		}

		if remainingTempRecords == 0 {
			fmt.Printf("✓ All temporary records successfully deleted and verified\n")
		} else {
			fmt.Printf("✗ %d temporary records still exist after deletion\n", remainingTempRecords)
		}
	} else {
		fmt.Printf("ERROR: No temporary records were found after creation\n")
	}

	// Clean up libdns-test records that were created during testing
	fmt.Printf("\nCleaning up libdns-test records...\n")

	// Get all records to find libdns-test records
	cleanupRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("ERROR getting records for cleanup: %s\n", err.Error())
		return
	}

	// Find all libdns-test records
	var libdnsTestRecords []libdns.Record
	for _, record := range cleanupRecords {
		if record.RR().Name == testName {
			libdnsTestRecords = append(libdnsTestRecords, record)
			fmt.Printf("Found libdns-test record to delete: %s: %s, %s\n", record.RR().Name, record.RR().Type, record.RR().Data)
		}
	}

	if len(libdnsTestRecords) > 0 {
		fmt.Printf("Deleting %d libdns-test records...\n", len(libdnsTestRecords))

		// Delete records one by one to ensure all are removed
		for i, record := range libdnsTestRecords {
			fmt.Printf("Deleting libdns-test record %d/%d: %s\n", i+1, len(libdnsTestRecords), record.RR().Data)
			_, err = provider.DeleteRecords(context.TODO(), zone, []libdns.Record{record})
			if err != nil {
				fmt.Printf("ERROR deleting libdns-test record %d: %s\n", i+1, err.Error())
				return
			}
		}
		fmt.Printf("Successfully deleted all libdns-test records\n")

		// Verify the libdns-test records were deleted
		finalCleanupRecords, err := provider.GetRecords(context.TODO(), zone)
		if err != nil {
			fmt.Printf("ERROR getting final cleanup records: %s\n", err.Error())
			return
		}

		remainingLibdnsTestRecords := 0
		for _, record := range finalCleanupRecords {
			if record.RR().Name == testName {
				remainingLibdnsTestRecords++
			}
		}

		if remainingLibdnsTestRecords == 0 {
			fmt.Printf("✓ All libdns-test records successfully deleted and verified\n")
		} else {
			fmt.Printf("✗ %d libdns-test records still exist after deletion\n", remainingLibdnsTestRecords)
		}
	} else {
		fmt.Printf("No libdns-test records found to clean up\n")
	}

	fmt.Printf("\nExample completed successfully! All test records have been cleaned up.\n")
}
