package ragclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type RetrieveRequest struct {
	Primitive string `json:"primitive"`
	Usage     string `json:"usage"`
	TopK      int    `json:"top_k"`
}

type Chunk struct {
	Text    string  `json:"text"`
	Source  string  `json:"source"`
	Section string  `json:"section"`
	Score   float64 `json:"score"`
}

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Retrieve(ctx context.Context, req RetrieveRequest) ([]Chunk, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/retrieve", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, fmt.Errorf("RAG service unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RAG service returned %d", resp.StatusCode)
	}
	var chunks []Chunk
	if err := json.NewDecoder(resp.Body).Decode(&chunks); err != nil {
		return nil, err
	}
	return chunks, nil
}
