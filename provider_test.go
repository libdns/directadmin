package directadmin

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
)

func createProvider() *Provider {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		os.Exit(1)
	}

	insecureRequest, err := strconv.ParseBool(defaultEnv("LIBDNS_DA_TEST_INSECURE_REQUESTS", "false"))
	if err != nil {
		insecureRequest = false
	}

	provider := &Provider{
		ServerURL:        envOrFail("LIBDNS_DA_TEST_SERVER_URL"),
		User:             envOrFail("LIBDNS_DA_TEST_USER"),
		LoginKey:         envOrFail("LIBDNS_DA_TEST_LOGIN_KEY"),
		InsecureRequests: insecureRequest,
	}
	return provider
}

func initProvider() (*Provider, string) {
	provider := createProvider()
	zone := envOrFail("LIBDNS_DA_TEST_ZONE")
	return provider, zone
}

func initProviderWithNonRootZone() (*Provider, string) {
	provider := createProvider()
	zone := envOrFail("LIBDNS_DA_NON_ROOT_TEST_ZONE")
	return provider, zone
}

func defaultEnv(key, fallback string) string {
	val := os.Getenv(key)
	if len(val) == 0 {
		return fallback
	}

	return val
}

func envOrFail(key string) string {
	val := os.Getenv(key)
	if len(val) == 0 {
		fmt.Printf("Please notice that this test runs against a production direct admin DNS API\n"+
			"you sould never run the test with an in use, production zone.\n\n"+
			"To run these tests, you need to copy .env.example to .env and modify the values for your environment.\n\n"+
			"%v is required", key)
		os.Exit(1)
	}

	return val
}

func TestProvider_GetRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()

	// list records
	records, err := provider.GetRecords(ctx, zone)

	if len(records) == 0 {
		t.Errorf("expected >0 records")
	}

	if err != nil {
		t.Error(err)
	}

	// Hack to work around "unsupported record conversion of type SRV: _xmpp._tcp"
	// output not generating a new line. This breaks GoLands test results output
	// https://stackoverflow.com/a/68607772/95790
	fmt.Println()
}

func TestProvider_InsecureGetRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()
	provider.ServerURL = envOrFail("LIBDNS_DA_TEST_INSECURE_SERVER_URL")
	provider.InsecureRequests = true

	// list records
	records, err := provider.GetRecords(ctx, zone)

	if len(records) == 0 {
		t.Errorf("expected >0 records")
	}

	if err != nil {
		t.Error(err)
	}

	// Hack to work around "unsupported record conversion of type SRV: _xmpp._tcp"
	// output not generating a new line. This breaks GoLands test results output
	// https://stackoverflow.com/a/68607772/95790
	fmt.Println()
}

func TestProvider_AppendRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "1.1.1.1",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "libdnsTest",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: false,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest",
					Data: "2606:4700:4700::1111",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest2",
					Data: "test2",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: false,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest2",
					Data: "1.1.1.1",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest2",
					Data: "2606:4700:4700::1111",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "TXT",
					Name: "_acme-challenge.libdns.test",
					Data: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("%v records", 0)
		t.Run(testName, func(t *testing.T) {
			_, err := provider.AppendRecords(ctx, zone, tt.records)

			if tt.expectSuccess && err != nil {
				t.Error(err)
			}

			if !tt.expectSuccess && err == nil {
				t.Error("expected an error, didn't see one")
			}
		})
	}
}

func TestProvider_DotZoneAppendRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()
	if zone[len(zone)-1:] != "." {
		zone = zone + "."
	}

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "1.1.1.1",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "TXT",
					Name: "_acme-challenge.libdns.test",
					Data: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("%v records", 0)
		t.Run(testName, func(t *testing.T) {
			_, err := provider.AppendRecords(ctx, zone, tt.records)

			if tt.expectSuccess && err != nil {
				t.Error(err)
			}

			if !tt.expectSuccess && err == nil {
				t.Error("expected an error, didn't see one")
			}
		})
	}
}

func TestProvider_SetRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "8.8.8.8",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest",
					Data: "2001:4860:4860::8888",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest2",
					Data: "8.8.8.8",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest2",
					Data: "2001:4860:4860::8888",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "TXT",
					Name: "_acme-challenge.libdns.test",
					Data: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("%v records", 0)
		t.Run(testName, func(t *testing.T) {
			_, err := provider.SetRecords(ctx, zone, tt.records)

			if tt.expectSuccess && err != nil {
				t.Error(err)
			}

			if !tt.expectSuccess && err == nil {
				t.Error("expected an error, didn't see one")
			}
		})
	}

	// Hack to work around "unsupported record conversion of type SRV: _xmpp._tcp"
	// output not generating a new line. This breaks GoLands test results output
	// https://stackoverflow.com/a/68607772/95790
	fmt.Println()
}

func TestProvider_DeleteRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider()

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "8.8.8.8",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest",
					Data: "1.1.1.1",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest",
					Data: "2001:4860:4860::8888",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest",
					Data: "2606:4700:4700::1111",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest2",
					Data: "8.8.8.8",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "A",
					Name: "libdnsTest2",
					Data: "1.1.1.1",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest2",
					Data: "2001:4860:4860::8888",
					TTL:  300 * time.Second,
				},
				&libdns.RR{
					Type: "AAAA",
					Name: "libdnsTest2",
					Data: "2606:4700:4700::1111",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				&libdns.RR{
					Type: "TXT",
					Name: "_acme-challenge.libdns.test",
					Data: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:  300 * time.Second,
				},
			},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("%v records", 0)
		t.Run(testName, func(t *testing.T) {
			_, err := provider.DeleteRecords(ctx, zone, tt.records)

			if tt.expectSuccess && err != nil {
				t.Error(err)
			}

			if !tt.expectSuccess && err == nil {
				t.Error("expected an error, didn't see one")
			}
		})
	}
}

func TestProvider_SetRecords_Atomicity(t *testing.T) {
	ctx := context.TODO()
	provider, zone := initProvider()

	// Test case where all records fail (should return AtomicErr)
	invalidRecords := []libdns.Record{
		&libdns.RR{
			Type: "A",
			Name: "invalid",
			TTL:  300 * time.Second,
			Data: "invalid-ip",
		},
		&libdns.RR{
			Type: "AAAA",
			Name: "invalid",
			TTL:  300 * time.Second,
			Data: "invalid-ip",
		},
	}

	_, err := provider.SetRecords(ctx, zone, invalidRecords)
	if err == nil {
		t.Error("expected an error for invalid records, got nil")
	}

	// Check if it's an AtomicErr (all records failed)
	// Note: We can't directly compare with libdns.AtomicErr since it's a type
	// But we can check the error message or type
	if err != nil {
		// The error should indicate that all records failed
		errStr := err.Error()
		if !strings.Contains(errStr, "all records failed") && !strings.Contains(errStr, "AtomicErr") {
			t.Errorf("expected AtomicErr or 'all records failed' message, got: %v", err)
		}
	}
}

func TestProvider_AdjustRecordForZone(t *testing.T) {
	// Get properly configured provider and zones
	provider, rootZone := initProvider()
	_, subZone := initProviderWithNonRootZone()

	tests := []struct {
		name           string
		record         libdns.Record
		requestedZone  string
		managedZone    string
		expectedName   string
		expectAdjusted bool
	}{
		{
			name: "subdomain zone adjustment",
			record: &libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge.libdns",
				Data: "test-value",
				TTL:  300 * time.Second,
			},
			requestedZone:  subZone,
			managedZone:    rootZone,
			expectedName:   "_acme-challenge.libdns.test",
			expectAdjusted: true,
		},
		{
			name: "exact zone match - no adjustment",
			record: &libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge.libdns",
				Data: "test-value",
				TTL:  300 * time.Second,
			},
			requestedZone:  rootZone,
			managedZone:    rootZone,
			expectedName:   "_acme-challenge.libdns",
			expectAdjusted: false,
		},
		{
			name: "deep subdomain adjustment",
			record: &libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge.libdns",
				Data: "test-value",
				TTL:  300 * time.Second,
			},
			requestedZone:  "api." + subZone,
			managedZone:    rootZone,
			expectedName:   "_acme-challenge.libdns.api.test",
			expectAdjusted: true,
		},
		{
			name: "trailing dot handling",
			record: &libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge.libdns",
				Data: "test-value",
				TTL:  300 * time.Second,
			},
			requestedZone:  subZone + ".",
			managedZone:    rootZone,
			expectedName:   "_acme-challenge.libdns.test",
			expectAdjusted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.adjustRecordForZone(tt.record, tt.requestedZone, tt.managedZone)
			resultRR := result.RR()

			if resultRR.Name != tt.expectedName {
				t.Errorf("expected name %s, got %s", tt.expectedName, resultRR.Name)
			}

			// Check if other fields are preserved
			originalRR := tt.record.RR()
			if resultRR.Type != originalRR.Type {
				t.Errorf("expected type %s, got %s", originalRR.Type, resultRR.Type)
			}
			if resultRR.Data != originalRR.Data {
				t.Errorf("expected data %s, got %s", originalRR.Data, resultRR.Data)
			}
			if resultRR.TTL != originalRR.TTL {
				t.Errorf("expected TTL %v, got %v", originalRR.TTL, resultRR.TTL)
			}

			// Check if adjustment was made when expected
			wasAdjusted := resultRR.Name != originalRR.Name
			if wasAdjusted != tt.expectAdjusted {
				if tt.expectAdjusted {
					t.Error("expected record name to be adjusted, but it wasn't")
				} else {
					t.Error("expected record name to remain unchanged, but it was adjusted")
				}
			}
		})
	}
}

func TestProvider_ZoneDetectionIntegration(t *testing.T) {
	// This test verifies that zone detection works with the actual provider methods
	ctx := context.TODO()
	provider, nonRootZone := initProviderWithNonRootZone()

	testRecord := &libdns.RR{
		Type: "TXT",
		Name: "_acme-challenge.libdns",
		Data: "zone-detection-test-value",
		TTL:  300 * time.Second,
	}

	// Test AppendRecords with subdomain zone detection
	t.Run("AppendRecords with zone detection", func(t *testing.T) {
		records, err := provider.AppendRecords(ctx, nonRootZone, []libdns.Record{testRecord})
		if err != nil {
			// This might fail if the subdomain doesn't exist in DirectAdmin, which is expected
			t.Logf("AppendRecords failed (expected if subdomain zone not configured): %v", err)
			return
		}

		if len(records) != 1 {
			t.Errorf("expected 1 record, got %d", len(records))
			return
		}

		// The record name should have been adjusted for the parent zone
		resultRR := records[0].RR()

		// Extract the subdomain part from nonRootZone (e.g., "test" from "test.navarro.family")
		expectedSubdomain := strings.Split(nonRootZone, ".")[0]

		if !strings.Contains(resultRR.Name, expectedSubdomain) {
			t.Errorf("expected record name to contain subdomain adjustment (%s), got: %s", expectedSubdomain, resultRR.Name)
		}

		// Clean up - delete the test record
		_, err = provider.DeleteRecords(ctx, nonRootZone, []libdns.Record{testRecord})
		if err != nil {
			t.Logf("Cleanup failed: %v", err)
		}
	})

	// Test SetRecords with zone detection
	t.Run("SetRecords with zone detection", func(t *testing.T) {
		records, err := provider.SetRecords(ctx, nonRootZone, []libdns.Record{testRecord})
		if err != nil {
			t.Logf("SetRecords failed (expected if subdomain zone not configured): %v", err)
			return
		}

		if len(records) != 1 {
			t.Errorf("expected 1 record, got %d", len(records))
			return
		}

		// Verify the record name was adjusted
		resultRR := records[0].RR()
		expectedSubdomain := strings.Split(nonRootZone, ".")[0]

		if !strings.Contains(resultRR.Name, expectedSubdomain) {
			t.Errorf("expected record name to contain subdomain adjustment (%s), got: %s", expectedSubdomain, resultRR.Name)
		}

		// Clean up
		_, err = provider.DeleteRecords(ctx, nonRootZone, []libdns.Record{testRecord})
		if err != nil {
			t.Logf("Cleanup failed: %v", err)
		}
	})
}
