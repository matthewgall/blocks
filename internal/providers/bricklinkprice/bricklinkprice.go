package bricklinkprice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/models"
)

type Client struct {
	httpClient *http.Client
	cache      cache.Cache
	ttl        time.Duration
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

type inventoryResponse struct {
	List []inventoryItem `json:"list"`
}

type inventoryItem struct {
	CodeNew          string `json:"codeNew"`
	DisplaySalePrice string `json:"mDisplaySalePrice"`
	Quantity         int    `json:"n4Qty"`
}

type inventorySummary struct {
	ItemID      int     `json:"item_id"`
	Currency    string  `json:"currency"`
	NewAverage  float64 `json:"new_average"`
	UsedAverage float64 `json:"used_average"`
	NewCount    int     `json:"new_count"`
	UsedCount   int     `json:"used_count"`
}

func New(cache cache.Cache, ttl time.Duration) *Client {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		ttl:        ttl,
	}
}

func (c *Client) GetInventoryAverage(ctx context.Context, setCode string, condition models.ItemCondition) (*Valuation, error) {
	setCode = normalizeSetCode(setCode)
	if setCode == "" {
		return nil, fmt.Errorf("set code required")
	}

	cacheKey := fmt.Sprintf("bricklink:inventory:%s", setCode)
	if c.cache != nil {
		cached, err := c.cache.Get(ctx, models.ProviderBrickLink, cacheKey)
		if err != nil {
			return nil, fmt.Errorf("checking cache: %w", err)
		}
		if cached != nil {
			var summary inventorySummary
			if err := json.Unmarshal([]byte(cached.PayloadJSON), &summary); err != nil {
				return nil, fmt.Errorf("unmarshaling cache: %w", err)
			}
			return summaryToValuation(summary, condition), nil
		}
	}

	itemID, err := fetchItemID(ctx, c.httpClient, setCode)
	if err != nil {
		return nil, err
	}

	inventoryURL := fmt.Sprintf("https://www.bricklink.com/ajax/clone/catalogifs.ajax?itemid=%d&iconly=0", itemID)
	response, err := fetchInventory(ctx, c.httpClient, inventoryURL)
	if err != nil {
		return nil, err
	}

	summary := summarizeInventory(itemID, response)
	if c.cache != nil {
		if err := c.cache.Set(ctx, models.ProviderBrickLink, cacheKey, summary, c.ttl, nil); err != nil {
			// Cache failure should not block valuation
		}
	}

	return summaryToValuation(summary, condition), nil
}

func fetchItemID(ctx context.Context, client *http.Client, setCode string) (int, error) {
	url := fmt.Sprintf("https://www.bricklink.com/catalogPG.asp?S=%s", setCode)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch bricklink page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bricklink request failed with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	re := regexp.MustCompile(`itemID=(\d+)`)
	match := re.FindStringSubmatch(string(body))
	if len(match) < 2 {
		return 0, fmt.Errorf("bricklink item id not found")
	}
	itemID, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("invalid item id")
	}
	return itemID, nil
}

func fetchInventory(ctx context.Context, client *http.Client, url string) (*inventoryResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inventory request failed with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload inventoryResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func summarizeInventory(itemID int, response *inventoryResponse) inventorySummary {
	var newPrices []float64
	var usedPrices []float64
	currency := ""
	if response != nil {
		for _, item := range response.List {
			price, curr := parseCurrency(item.DisplaySalePrice)
			if price <= 0 {
				continue
			}
			if currency == "" && curr != "" {
				currency = curr
			}
			if strings.EqualFold(item.CodeNew, "N") {
				newPrices = append(newPrices, price)
			} else if strings.EqualFold(item.CodeNew, "U") {
				usedPrices = append(usedPrices, price)
			}
		}
	}

	newAvg := average(newPrices)
	usedAvg := average(usedPrices)
	return inventorySummary{
		ItemID:      itemID,
		Currency:    currency,
		NewAverage:  newAvg,
		UsedAverage: usedAvg,
		NewCount:    len(newPrices),
		UsedCount:   len(usedPrices),
	}
}

func summaryToValuation(summary inventorySummary, condition models.ItemCondition) *Valuation {
	value := summary.UsedAverage
	sample := summary.UsedCount
	if condition == models.ConditionSealed {
		value = summary.NewAverage
		sample = summary.NewCount
	}
	if value <= 0 && summary.NewAverage > 0 {
		value = summary.NewAverage
		sample = summary.NewCount
	}
	if value <= 0 && summary.UsedAverage > 0 {
		value = summary.UsedAverage
		sample = summary.UsedCount
	}
	if value <= 0 {
		return &Valuation{
			Provider:  models.ProviderBrickLink,
			Currency:  summary.Currency,
			Condition: condition,
			Metric:    "inventory_avg",
			Value:     0,
			AsOfDate:  time.Now(),
		}
	}
	var sampleSize *int
	if sample > 0 {
		sampleSize = &sample
	}
	return &Valuation{
		Provider:   models.ProviderBrickLink,
		Currency:   summary.Currency,
		Condition:  condition,
		Metric:     "inventory_avg",
		Value:      value,
		SampleSize: sampleSize,
		AsOfDate:   time.Now(),
	}
}

func parseCurrency(value string) (float64, string) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return 0, ""
	}
	currency := ""
	upper := strings.ToUpper(clean)
	switch {
	case strings.HasPrefix(upper, "GBP") || strings.Contains(clean, "£"):
		currency = "GBP"
	case strings.HasPrefix(upper, "US $") || strings.HasPrefix(upper, "USD"):
		currency = "USD"
	case strings.HasPrefix(upper, "EUR") || strings.Contains(clean, "€"):
		currency = "EUR"
	case strings.HasPrefix(upper, "CA $"):
		currency = "CAD"
	}

	clean = strings.ReplaceAll(clean, "GBP", "")
	clean = strings.ReplaceAll(clean, "US $", "")
	clean = strings.ReplaceAll(clean, "CA $", "")
	clean = strings.ReplaceAll(clean, "EUR", "")
	clean = strings.ReplaceAll(clean, "£", "")
	clean = strings.ReplaceAll(clean, "€", "")
	clean = strings.ReplaceAll(clean, ",", "")
	clean = strings.TrimSpace(clean)
	parsed, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return 0, currency
	}
	return parsed, currency
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func normalizeSetCode(setCode string) string {
	trimmed := strings.TrimSpace(setCode)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "-") {
		return trimmed
	}
	return trimmed + "-1"
}
