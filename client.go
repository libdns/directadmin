package directadmin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"github.com/libdns/libdns"
)

func (p *Provider) getZoneRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	callerSkipDepth := 2

	reqURL, err := url.Parse(p.ServerURL)
	if err != nil {
		fmt.Printf("[%s] failed to parse server url: %v\n", p.caller(callerSkipDepth), err)
		return nil, err
	}

	reqURL.Path = "/CMD_API_DNS_CONTROL"

	queryString := make(url.Values)
	queryString.Set("json", "yes")
	queryString.Set("full_mx_records", "yes")
	queryString.Set("allow_dns_underscore", "yes")
	queryString.Set("ttl", "yes")
	queryString.Set("domain", zone)

	reqURL.RawQuery = queryString.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		fmt.Printf("[%s] failed to build new request: %v\n", p.caller(callerSkipDepth), err)
		return nil, err
	}

	req.SetBasicAuth(p.User, p.LoginKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: p.InsecureRequests,
			},
		}}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[%s] failed to execute request: %v\n", p.caller(callerSkipDepth), err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("[%s] failed to close body: %v\n", p.caller(callerSkipDepth), err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[%s] api response error, status code: %v\n", p.caller(callerSkipDepth), resp.StatusCode)
		return nil, err
	}

	var respData daZone
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		fmt.Printf("[%s] failed to json decode response: %v\n", p.caller(callerSkipDepth), err)
		return nil, err
	}

	recs := make([]libdns.Record, 0, len(respData.Records))
	for i := range respData.Records {
		libDnsRecord, err := respData.Records[i].libdnsRecord(zone)
		if err != nil {
			switch err {
			case ErrUnsupported:
				rr := libDnsRecord.RR()
				fmt.Printf("[%s] unsupported record conversion of type %v: %v\n", p.caller(callerSkipDepth), rr.Type, rr.Name)
				continue
			default:
				return nil, err
			}
		}
		recs = append(recs, libDnsRecord)
	}

	return recs, nil
}

func (p *Provider) appendZoneRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	reqURL, err := url.Parse(p.ServerURL)
	if err != nil {
		fmt.Printf("[%s] failed to parse server url: %v\n", p.caller(2), err)
		return nil, err
	}

	reqURL.Path = "/CMD_API_DNS_CONTROL"

	queryString := make(url.Values)
	queryString.Set("action", "add")
	queryString.Set("json", "yes")
	queryString.Set("full_mx_records", "yes")
	queryString.Set("allow_dns_underscore", "yes")
	queryString.Set("domain", zone)

	rr := record.RR()
	queryString.Set("type", rr.Type)
	queryString.Set("name", rr.Name)
	queryString.Set("value", rr.Data)

	if rr.Type != "NS" {
		queryString.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
	}

	reqURL.RawQuery = queryString.Encode()

	err = p.executeRequest(ctx, http.MethodGet, reqURL.String())
	if err != nil {
		return nil, err
	}

	rr.Data = fmt.Sprintf("name=%v&value=%v", rr.Name, rr.Data)
	return &rr, nil
}

func (p *Provider) setZoneRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	reqURL, err := url.Parse(p.ServerURL)
	if err != nil {
		fmt.Printf("[%s] failed to parse server url: %v\n", p.caller(2), err)
		return nil, err
	}

	reqURL.Path = "/CMD_API_DNS_CONTROL"

	queryString := make(url.Values)
	queryString.Set("action", "edit")
	queryString.Set("json", "yes")
	queryString.Set("domain", zone)

	rr := record.RR()
	queryString.Set("type", rr.Type)
	queryString.Set("name", rr.Name)
	queryString.Set("value", rr.Data)

	if rr.Type != "NS" {
		queryString.Set("ttl", strconv.Itoa(int(rr.TTL.Seconds())))
	}

	existingRecords, _ := p.getZoneRecords(ctx, zone)
	var existingRecordIndex = -1
	for i := range existingRecords {
		existingRR := existingRecords[i].RR()
		if existingRR.Name == rr.Name && existingRR.Type == rr.Type {
			existingRecordIndex = i
			break
		}
	}

	// If we're not -1, we found a matching existing record. This changes the API call
	// from create only to edit.
	if existingRecordIndex != -1 {
		editKey := fmt.Sprintf("%vrecs0", strings.ToLower(rr.Type))
		editValue := existingRecords[existingRecordIndex].RR().Data
		queryString.Set(editKey, editValue)
	}

	reqURL.RawQuery = queryString.Encode()

	err = p.executeRequest(ctx, http.MethodGet, reqURL.String())
	if err != nil {
		return nil, err
	}

	rr.Data = fmt.Sprintf("name=%v&value=%v", rr.Name, rr.Data)
	return &rr, nil
}

func (p *Provider) deleteZoneRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	reqURL, err := url.Parse(p.ServerURL)
	if err != nil {
		fmt.Printf("[%s] failed to parse server url: %v\n", p.caller(2), err)
		return nil, err
	}

	reqURL.Path = "/CMD_API_DNS_CONTROL"

	queryString := make(url.Values)
	queryString.Set("action", "select")
	queryString.Set("json", "yes")
	queryString.Set("domain", zone)

	rr := record.RR()
	editKey := fmt.Sprintf("%vrecs0", strings.ToLower(rr.Type))
	editValue := fmt.Sprintf("name=%v&value=%v", rr.Name, rr.Data)
	queryString.Set(editKey, editValue)

	reqURL.RawQuery = queryString.Encode()

	err = p.executeRequest(ctx, http.MethodGet, reqURL.String())
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (p *Provider) executeRequest(ctx context.Context, method, url string) error {
	callerSkipDepth := 3

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		fmt.Printf("[%s] failed to build new request: %v\n", p.caller(callerSkipDepth), err)
		return err
	}

	req.SetBasicAuth(p.User, p.LoginKey)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: p.InsecureRequests,
			},
		}}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[%s] failed to execute request: %v\n", p.caller(callerSkipDepth), err)
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("[%s] failed to close body: %v\n", p.caller(callerSkipDepth), err)
		}
	}(resp.Body)

	var respData daResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		fmt.Printf("[%s] failed to json decode response: %v\n", p.caller(callerSkipDepth), err)
		return err
	}

	if len(respData.Error) > 0 {
		trimmedResult := strings.Split(respData.Result, "\n")[0]
		fmt.Printf("[%s] api response error: %v: %v\n", p.caller(callerSkipDepth), respData.Error, trimmedResult)
		return fmt.Errorf("[%s] api response error: %v: %v\n", p.caller(callerSkipDepth), respData.Error, trimmedResult)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("[%s] failed to read response body: %v\n", p.caller(callerSkipDepth), err)
			return err
		}
		bodyString := string(bodyBytes)
		log.Println(bodyString)

		return err
	}

	return nil
}

func (p *Provider) caller(skip int) string {
	pc := make([]uintptr, 15)
	n := runtime.Callers(skip, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame.Function
}
