package directadmin

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
	"os"
	"strconv"
	"testing"
	"time"
)

func initProvider(nonRoot bool) (*Provider, string) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		os.Exit(1)
	}

	zone := envOrFail("LIBDNS_DA_TEST_ZONE")

	if nonRoot {
		zone = envOrFail("LIBDNS_DA_NON_ROOT_TEST_ZONE")
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
		fmt.Printf("Please note that these tests must run against a real direct admin DNS API\n"+
			"you should never run these tests against an in use, production zone.\n\n"+
			"To run these tests, you need to copy .env.example to .env and modify the values for your environment.\n\n"+
			"%v is required", key)
		os.Exit(1)
	}

	return val
}

func TestProvider_GetRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider(false)

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
	provider, zone := initProvider(false)
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
	provider, zone := initProvider(false)

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest",
					Value: "1.1.1.1",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest",
					Value: "libdnsTest",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: false,
		},
		{
			records: []libdns.Record{
				{
					Type:  "AAAA",
					Name:  "libdnsTest",
					Value: "2606:4700:4700::1111",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "AAAA",
					Name:  "libdnsTest2",
					Value: "test2",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: false,
		},
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest2",
					Value: "1.1.1.1",
					TTL:   300 * time.Second,
				},
				{
					Type:  "AAAA",
					Name:  "libdnsTest2",
					Value: "2606:4700:4700::1111",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "TXT",
					Name:  "_acme-challenge.libdns.test",
					Value: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:   300 * time.Second,
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
	provider, zone := initProvider(false)
	if zone[len(zone)-1:] != "." {
		zone = zone + "."
	}

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest",
					Value: "1.1.1.1",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "TXT",
					Name:  "_acme-challenge.libdns.test",
					Value: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:   300 * time.Second,
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

func TestProvider_NonRootAppendRecords(t *testing.T) {
	ctx := context.TODO()

	// Configure the DNS provider
	provider, zone := initProvider(true)
	if zone[len(zone)-1:] != "." {
		zone = zone + "."
	}

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				{
					Type:  "TXT",
					Name:  "_acme-challenge.libdns",
					Value: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:   0,
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
	provider, zone := initProvider(false)

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest",
					Value: "8.8.8.8",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "AAAA",
					Name:  "libdnsTest",
					Value: "2001:4860:4860::8888",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest2",
					Value: "8.8.8.8",
					TTL:   300 * time.Second,
				},
				{
					Type:  "AAAA",
					Name:  "libdnsTest2",
					Value: "2001:4860:4860::8888",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "TXT",
					Name:  "_acme-challenge.libdns.test",
					Value: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:   300 * time.Second,
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
	provider, zone := initProvider(false)

	var tests = []struct {
		records       []libdns.Record
		expectSuccess bool
	}{
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest",
					Value: "8.8.8.8",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "AAAA",
					Name:  "libdnsTest",
					Value: "2001:4860:4860::8888",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "A",
					Name:  "libdnsTest2",
					Value: "8.8.8.8",
					TTL:   300 * time.Second,
				},
				{
					Type:  "AAAA",
					Name:  "libdnsTest2",
					Value: "2001:4860:4860::8888",
					TTL:   300 * time.Second,
				},
			},
			expectSuccess: true,
		},
		{
			records: []libdns.Record{
				{
					Type:  "TXT",
					Name:  "_acme-challenge.libdns.test",
					Value: "bI8-MNaHRF2FYODzDV2QIWDJrtN94tHqUjHFU_m1tIY",
					TTL:   300 * time.Second,
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
