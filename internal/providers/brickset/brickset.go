package brickset

import (
	"context"
	"database/sql"
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
	dailyLimit int
	cacheTTL   time.Duration
}

type SetRequest struct {
	SetNumber    string `json:"setNumber"`
	SetID        string `json:"setID,omitempty"`
	ExtendedData int    `json:"extendedData"`
	PageSize     int    `json:"pageSize"`
	PageNumber   int    `json:"pageNumber"`
	UserHash     string `json:"userHash,omitempty"`
	OrderBy      string `json:"orderBy,omitempty"`
	Query        string `json:"query,omitempty"`
	Theme        string `json:"theme,omitempty"`
	Subtheme     string `json:"subtheme,omitempty"`
	Year         string `json:"year,omitempty"`
}

type SetResponse struct {
	Sets    []BricksetSet `json:"sets"`
	Matches int           `json:"matches"`
}

type BricksetSet struct {
	SetID          string `json:"setID"`
	Number         string `json:"number"`
	Name           string `json:"name"`
	Year           int    `json:"year"`
	Theme          string `json:"theme"`
	Subtheme       string `json:"subtheme"`
	Category       string `json:"category"`
	Pieces         int    `json:"pieces"`
	Minifigs       int    `json:"minifigs"`
	ImageURL       string `json:"imageURL"`
	ThumbnailURL   string `json:"thumbnailURL"`
	LastModifiedDT string `json:"lastModifiedDT"`
}

type DailyUsage struct {
	Date  string
	Count int
}

func New(cfg *config.BricksetConfig, cache cache.Cache, cacheTTL time.Duration) *Client {
	return &Client{
		apiKey:  cfg.APIKey,
		baseURL: "https://brickset.com/api/v3.asmx",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:      cache,
		dailyLimit: cfg.DailyLimit,
		cacheTTL:   cacheTTL,
	}
}

func (c *Client) GetSetByNumber(ctx context.Context, setNumber string) (*BricksetSet, error) {
	cacheKey := fmt.Sprintf("set:%s", setNumber)

	cached, err := c.cache.Get(ctx, models.ProviderBrickset, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result BricksetSet
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return &result, nil
	}

	if err := c.checkDailyLimit(ctx); err != nil {
		return nil, err
	}

	req := SetRequest{
		SetNumber:    setNumber,
		ExtendedData: 1,
		PageSize:     1,
	}

	response, err := c.makeRequest(ctx, "getSets", req)
	if err != nil {
		return nil, err
	}

	if len(response.Sets) == 0 {
		return nil, fmt.Errorf("set not found: %s", setNumber)
	}

	set := &response.Sets[0]

	if err := c.cache.Set(ctx, models.ProviderBrickset, cacheKey, set, c.cacheTTL, nil); err != nil {
		log.Printf("Warning: failed to cache set %s: %v", setNumber, err)
	}

	return set, nil
}

func (c *Client) GetSetByID(ctx context.Context, setID string) (*BricksetSet, error) {
	cacheKey := fmt.Sprintf("set_id:%s", setID)

	cached, err := c.cache.Get(ctx, models.ProviderBrickset, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result BricksetSet
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return &result, nil
	}

	if err := c.checkDailyLimit(ctx); err != nil {
		return nil, err
	}

	req := SetRequest{
		SetID:        setID,
		ExtendedData: 1,
		PageSize:     1,
	}

	response, err := c.makeRequest(ctx, "getSets", req)
	if err != nil {
		return nil, err
	}

	if len(response.Sets) == 0 {
		return nil, fmt.Errorf("set not found: %s", setID)
	}

	set := &response.Sets[0]

	if err := c.cache.Set(ctx, models.ProviderBrickset, cacheKey, set, c.cacheTTL, nil); err != nil {
		log.Printf("Warning: failed to cache set %s: %v", setID, err)
	}

	return set, nil
}

func (c *Client) SearchSets(ctx context.Context, query string) ([]BricksetSet, error) {
	cacheKey := fmt.Sprintf("search:%s", url.QueryEscape(query))

	cached, err := c.cache.Get(ctx, models.ProviderBrickset, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result []BricksetSet
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return result, nil
	}

	if err := c.checkDailyLimit(ctx); err != nil {
		return nil, err
	}

	req := SetRequest{
		Query:        query,
		ExtendedData: 1,
		PageSize:     50,
	}

	response, err := c.makeRequest(ctx, "getSets", req)
	if err != nil {
		return nil, err
	}

	if err := c.cache.Set(ctx, models.ProviderBrickset, cacheKey, response.Sets, c.cacheTTL, nil); err != nil {
		log.Printf("Warning: failed to cache search results for %s: %v", query, err)
	}

	return response.Sets, nil
}

func (c *Client) makeRequest(ctx context.Context, method string, request interface{}) (*SetResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/%s", c.baseURL, method)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	q := req.URL.Query()
	q.Add("apiKey", c.apiKey)
	q.Add("params", string(requestBody))
	req.URL.RawQuery = q.Encode()

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

	if err := c.incrementDailyUsage(ctx); err != nil {
		log.Printf("Warning: failed to increment daily usage: %v", err)
	}

	return &response, nil
}

func (c *Client) checkDailyLimit(ctx context.Context) error {
	today := time.Now().Format("2006-01-02")

	var count int
	err := c.cache.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM external_cache 
		WHERE provider = 'brickset_daily_limit' AND cache_key = ? 
		AND date(fetched_at) = date('now')
	`, today).Scan(&count)

	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("checking daily limit: %w", err)
	}

	if count >= c.dailyLimit {
		return fmt.Errorf("daily Brickset API limit of %d has been reached", c.dailyLimit)
	}

	return nil
}

func (c *Client) incrementDailyUsage(ctx context.Context) error {
	today := time.Now().Format("2006-01-02")

	_, err := c.cache.DB().ExecContext(ctx, `
		INSERT OR IGNORE INTO external_cache 
		(provider, cache_key, payload_json, ttl_seconds)
		VALUES ('brickset_daily_limit', ?, '1', 86400)
	`, today)

	return err
}

func (c *Client) GetDailyUsage(ctx context.Context) ([]DailyUsage, error) {
	rows, err := c.cache.DB().QueryContext(ctx, `
		SELECT cache_key, COUNT(*) as count 
		FROM external_cache 
		WHERE provider = 'brickset_daily_limit'
		GROUP BY cache_key
		ORDER BY cache_key DESC
		LIMIT 30
	`)
	if err != nil {
		return nil, fmt.Errorf("querying daily usage: %w", err)
	}
	defer rows.Close()

	var usage []DailyUsage
	for rows.Next() {
		var u DailyUsage
		if err := rows.Scan(&u.Date, &u.Count); err != nil {
			return nil, fmt.Errorf("scanning usage row: %w", err)
		}
		usage = append(usage, u)
	}

	return usage, nil
}
