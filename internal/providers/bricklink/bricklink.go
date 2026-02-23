//go:build bricklink
// +build bricklink

package bricklink

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/config"
	"github.com/matthewgall/blocks/internal/models"
)

type Client struct {
	consumerKey    string
	consumerSecret string
	token          string
	tokenSecret    string
	baseURL        string
	httpClient     *http.Client
	cache          cache.Cache
}

type PriceGuideRequest struct {
	Type         string `json:"type"`
	ItemNo       string `json:"item_no"`
	ItemTypeID   int    `json:"item_type_id"`
	NewOrUsed    string `json:"new_or_used"`
	CountryCode  string `json:"country_code"`
	CurrencyCode string `json:"currency_code"`
	GuideType    string `json:"guide_type"`
	MaxQuantity  int    `json:"max_quantity"`
}

type PriceGuideResponse struct {
	PriceGuideData struct {
		ItemNo      string `json:"item_no"`
		ItemTypeID  int    `json:"item_type_id"`
		PriceDetail []struct {
			Qty          int     `json:"qty"`
			Price        float64 `json:"price"`
			Shipping     float64 `json:"shipping"`
			CountryCode  string  `json:"country_code"`
			CurrencyCode string  `json:"currency_code"`
		} `json:"price_detail"`
		AvgPrice      float64 `json:"avg_price"`
		MinPrice      float64 `json:"min_price"`
		MaxPrice      float64 `json:"max_price"`
		TotalQuantity int     `json:"total_quantity"`
		UnitPrice     float64 `json:"unit_price"`
		CurrencyCode  string  `json:"currency_code"`
		LastUpdated   string  `json:"last_updated"`
	} `json:"price_guide_data"`
}

type Valuation struct {
	Provider   models.Provider      `json:"provider"`
	Currency   string               `json:"currency"`
	Condition  models.ItemCondition `json:"condition"`
	Metric     string               `json:"metric"`
	Value      float64              `json:"value"`
	SampleSize *int                 `json:"sample_size"`
	Confidence *int                 `json:"confidence"`
	AsOfDate   time.Time            `json:"as_of_date"`
	RawJSON    *string              `json:"raw_json"`
}

func New(cfg *config.BrickLinkConfig, cache cache.Cache) *Client {
	return &Client{
		consumerKey:    cfg.ConsumerKey,
		consumerSecret: cfg.ConsumerSecret,
		token:          cfg.Token,
		tokenSecret:    cfg.TokenSecret,
		baseURL:        "https://www.bricklink.com/v3/api.page",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: cache,
	}
}

func (c *Client) GetPriceGuide(ctx context.Context, setNumber string, condition models.ItemCondition, currency string) (*Valuation, error) {
	cacheKey := fmt.Sprintf("priceguide:%s:%s:%s", setNumber, condition, currency)

	cached, err := c.cache.Get(ctx, models.ProviderBrickLink, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}

	if cached != nil {
		var result Valuation
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return &result, nil
	}

	blCondition := "U"
	if condition == models.ConditionSealed {
		blCondition = "N"
	}

	params := url.Values{}
	params.Set("page", "get-price-guide")
	params.Set("type", "set")
	params.Set("item_no", setNumber)
	params.Set("new_or_used", blCondition)
	params.Set("country_code", "US")
	params.Set("currency_code", currency)
	params.Set("guide_type", "sold")

	reqURL := c.baseURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.signRequest(req, params)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response PriceGuideResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if response.PriceGuideData.ItemNo == "" {
		return nil, fmt.Errorf("no price guide data found for set %s", setNumber)
	}

	rawJSON, _ := json.Marshal(response.PriceGuideData)
	rawJSONStr := string(rawJSON)

	valuation := &Valuation{
		Provider:   models.ProviderBrickLink,
		Currency:   response.PriceGuideData.CurrencyCode,
		Condition:  condition,
		Metric:     "sold_last_6m_avg",
		Value:      response.PriceGuideData.AvgPrice,
		SampleSize: &response.PriceGuideData.TotalQuantity,
		Confidence: c.calculateConfidence(response.PriceGuideData.TotalQuantity),
		AsOfDate:   time.Now(),
		RawJSON:    &rawJSONStr,
	}

	if err := c.cache.Set(ctx, models.ProviderBrickLink, cacheKey, valuation, 7*24*time.Hour, nil); err != nil {
		log.Printf("Warning: failed to cache valuation for %s: %v", setNumber, err)
	}

	return valuation, nil
}

func (c *Client) signRequest(req *http.Request, params url.Values) {
	timestamp := time.Now().Format("20060102T150405Z")

	params.Set("oauth_consumer_key", c.consumerKey)
	params.Set("oauth_token", c.token)
	params.Set("oauth_signature_method", "HMAC-SHA256")
	params.Set("oauth_timestamp", timestamp)
	params.Set("oauth_version", "1.0")

	signingKey := c.encode(c.consumerSecret) + "&" + c.encode(c.tokenSecret)

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var paramPairs []string
	for _, k := range keys {
		paramPairs = append(paramPairs, fmt.Sprintf("%s=%s", c.encode(k), c.encode(params.Get(k))))
	}

	paramString := strings.Join(paramPairs, "&")
	baseString := strings.ToUpper(req.Method) + "&" + c.encode(req.URL.String()) + "&" + c.encode(paramString)

	hash := hmac.New(sha256.New, []byte(signingKey))
	hash.Write([]byte(baseString))
	signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	params.Set("oauth_signature", signature)
	req.URL.RawQuery = params.Encode()
}

func (c *Client) encode(s string) string {
	return url.QueryEscape(s)
}

func (c *Client) calculateConfidence(sampleSize int) *int {
	confidence := 0
	if sampleSize >= 100 {
		confidence = 90
	} else if sampleSize >= 50 {
		confidence = 75
	} else if sampleSize >= 20 {
		confidence = 60
	} else if sampleSize >= 10 {
		confidence = 45
	} else if sampleSize >= 5 {
		confidence = 30
	} else if sampleSize >= 1 {
		confidence = 15
	}
	return &confidence
}
