package rebrickable

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/config"
	"github.com/matthewgall/blocks/internal/models"
)

type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	cache      cache.Cache
	cacheTTL   time.Duration
}

type RebrickableSet struct {
	SetNum         string `json:"set_num"`
	Name           string `json:"name"`
	Year           int    `json:"year"`
	ThemeID        int    `json:"theme_id"`
	NumParts       int    `json:"num_parts"`
	SetImgURL      string `json:"set_img_url"`
	LastModifiedDt string `json:"last_modified_dt"`
}

type SetResponse struct {
	Count    int              `json:"count"`
	Next     *string          `json:"next"`
	Previous *string          `json:"previous"`
	Results  []RebrickableSet `json:"results"`
}

func New(cfg *config.RebrickableConfig, cache cache.Cache, cacheTTL time.Duration) *Client {
	return &Client{
		apiKey:  cfg.APIKey,
		baseURL: "https://rebrickable.com/api/v3/lego/sets",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    cache,
		cacheTTL: cacheTTL,
	}
}

func (c *Client) GetSetByNumber(ctx context.Context, setNumber string) (*RebrickableSet, error) {
	cacheKey := fmt.Sprintf("set:%s", setNumber)

	cached, err := c.cache.Get(ctx, models.ProviderRebrickable, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result RebrickableSet
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return &result, nil
	}

	reqURL := fmt.Sprintf("%s/%s/", c.baseURL, url.PathEscape(setNumber))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "key "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	// #nosec G704 -- request targets a fixed rebrickable domain.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("set not found: %s", setNumber)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var set RebrickableSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if err := c.cache.Set(ctx, models.ProviderRebrickable, cacheKey, set, c.cacheTTL, nil); err != nil {
		log.Printf("Warning: failed to cache set %s: %v", setNumber, err)
	}

	return &set, nil
}

func (c *Client) SearchSets(ctx context.Context, query string) ([]RebrickableSet, error) {
	cacheKey := fmt.Sprintf("search:%s", url.QueryEscape(query))

	cached, err := c.cache.Get(ctx, models.ProviderRebrickable, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result []RebrickableSet
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return result, nil
	}

	reqURL := fmt.Sprintf("%s/?search=%s&ordering=year", c.baseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "key "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	// #nosec G704 -- request targets a fixed rebrickable domain.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response SetResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if err := c.cache.Set(ctx, models.ProviderRebrickable, cacheKey, response.Results, c.cacheTTL, nil); err != nil {
		log.Printf("Warning: failed to cache search results for %s: %v", query, err)
	}

	return response.Results, nil
}
