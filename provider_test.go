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

func initProvider() (*Provider, string) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		os.Exit(1)
	}

	zone := envOrFail("LIBDNS_DA_TEST_ZONE")

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
