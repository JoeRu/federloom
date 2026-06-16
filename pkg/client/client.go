package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a thin HTTP client for the local SwarmGuard API (spec §3).
type Client struct {
	baseURL string
	hc      *http.Client
}

// New creates a Client targeting baseURL (e.g. "http://localhost:9102").
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 10 * time.Second},
	}
}

// ScoreResponse is the JSON payload returned by GET /api/v1/score/{ip}.
type ScoreResponse struct {
	IP            string   `json:"ip"`
	Score         float64  `json:"score"`
	Corroboration int      `json:"corroboration"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	Reasons       []string `json:"reasons"`
	Blocked       bool     `json:"blocked"`
}

// BlockEntry is one row in the blocklist response.
type BlockEntry struct {
	IP       string    `json:"ip"`
	Score    float64   `json:"score"`
	LastSeen time.Time `json:"last_seen"`
	Reasons  []string  `json:"reasons"`
}

// BlocklistOpts filters the blocklist query.
type BlocklistOpts struct {
	MinScore float64  // 0 = use server default (block threshold)
	Purpose  string   // "mail", "web", "ssh", "" = all
	Reasons  []string // exact or wildcard patterns; nil = no filter
}

// EventMsg mirrors api.EventMsg (avoid importing internal packages from pkg/).
type EventMsg struct {
	IP       string    `json:"ip"`
	Score    float64   `json:"score"`
	Reason   string    `json:"reason"`
	Reporter string    `json:"reporter"`
	TS       time.Time `json:"ts"`
}

// ScoreIP fetches the reputation score for a single IP.
// Returns an error if the IP is not found (404) or the request fails.
func (c *Client) ScoreIP(ctx context.Context, ip string) (*ScoreResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/score/"+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("client: %s not found", ip)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: score returned %d", resp.StatusCode)
	}

	var score ScoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&score); err != nil {
		return nil, fmt.Errorf("client: decode score: %w", err)
	}
	return &score, nil
}

// Blocklist returns all IPs matching opts from the local API.
func (c *Client) Blocklist(ctx context.Context, opts BlocklistOpts) ([]BlockEntry, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/blocklist")
	if err != nil {
		return nil, err
	}

	q := u.Query()
	if opts.MinScore > 0 {
		q.Set("min_score", fmt.Sprintf("%g", opts.MinScore))
	}
	if opts.Purpose != "" {
		q.Set("purpose", opts.Purpose)
	}
	if len(opts.Reasons) > 0 {
		q.Set("reason", strings.Join(opts.Reasons, ","))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: blocklist returned %d", resp.StatusCode)
	}

	var entries []BlockEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("client: decode blocklist: %w", err)
	}
	return entries, nil
}

// Events subscribes to the SSE stream and returns a channel of EventMsg.
// The channel is closed when ctx is cancelled or the stream ends.
func (c *Client) Events(ctx context.Context) (<-chan EventMsg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/events", nil)
	if err != nil {
		return nil, err
	}
	// Use a client with no timeout for streaming.
	sseClient := &http.Client{}
	resp, err := sseClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("client: events returned %d", resp.StatusCode)
	}

	ch := make(chan EventMsg, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if data == "connected" {
				continue
			}
			var msg EventMsg
			if err := json.Unmarshal([]byte(data), &msg); err != nil {
				continue
			}
			select {
			case ch <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}
