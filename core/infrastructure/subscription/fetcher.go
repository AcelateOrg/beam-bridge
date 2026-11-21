package subscription

import (
	"errors"
	"io"
	"net/http"
	"time"
)

var (
	ErrInvalidURL    = errors.New("invalid subscription URL")
	ErrFetchFailed   = errors.New("failed to fetch the subscription")
	ErrInvalidConfig = errors.New("invalid config")
)

type Fetcher struct {
	client *http.Client
}

func NewFetcher(client *http.Client) *Fetcher {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Fetcher{client: client}
}

func (f *Fetcher) Fetch(url string, headers map[string]string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, ErrInvalidURL
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, ErrFetchFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, ErrFetchFailed
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, ErrFetchFailed
	}
	return body, resp.Header, nil
}
