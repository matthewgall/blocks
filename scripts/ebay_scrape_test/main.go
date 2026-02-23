package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type scrapeResult struct {
	Query        string  `json:"query"`
	SourceURL    string  `json:"source_url"`
	SampleSize   int     `json:"sample_size"`
	TrimmedSize  int     `json:"trimmed_size"`
	AveragePrice float64 `json:"average_price"`
	MinPrice     float64 `json:"min_price"`
	MaxPrice     float64 `json:"max_price"`
	Currency     string  `json:"currency"`
	Warning      string  `json:"warning,omitempty"`
}

func main() {
	setCode := flag.String("set", "", "LEGO set code (e.g., 10311-1)")
	query := flag.String("query", "", "Search query override")
	flag.Parse()

	search := strings.TrimSpace(*query)
	if search == "" {
		setValue := strings.TrimSpace(*setCode)
		if setValue == "" {
			fmt.Fprintln(os.Stderr, "query or set is required")
			os.Exit(1)
		}
		search = "LEGO " + stripSetVariant(setValue)
	}

	result, err := scrapeEbaySold(search)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func scrapeEbaySold(query string) (*scrapeResult, error) {
	encoded := url.QueryEscape(query)
	sourceURL := fmt.Sprintf("https://www.ebay.co.uk/sch/i.html?_nkw=%s&_sacat=0&LH_Sold=1&LH_Complete=1", encoded)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// #nosec G704 -- request targets a fixed ebay domain.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ebay page: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ebay request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	prices := extractGBPPrices(string(body), query)
	if len(prices) == 0 {
		return &scrapeResult{
			Query:     query,
			SourceURL: sourceURL,
			Currency:  "GBP",
			Warning:   "no prices found",
		}, nil
	}

	sort.Float64s(prices)
	trimmed := trimOutliers(prices, 0.2)
	if len(trimmed) == 0 {
		trimmed = prices
	}

	avg, min, max := summarizePrices(trimmed)
	result := &scrapeResult{
		Query:        query,
		SourceURL:    sourceURL,
		SampleSize:   len(prices),
		TrimmedSize:  len(trimmed),
		AveragePrice: avg,
		MinPrice:     min,
		MaxPrice:     max,
		Currency:     "GBP",
	}

	if len(prices) < 5 {
		result.Warning = "low sample size"
	}

	return result, nil
}

func stripSetVariant(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "-")
	if len(parts) == 0 {
		return trimmed
	}
	return parts[0]
}

func extractSetCode(query string) string {
	parts := strings.Fields(query)
	for _, part := range parts {
		clean := strings.Trim(part, "-#")
		if len(clean) >= 4 && len(clean) <= 7 {
			if allDigits(clean) {
				return clean
			}
		}
	}
	return ""
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func extractGBPPrices(html string, query string) []float64 {
	setCode := extractSetCode(query)
	if setCode == "" {
		return extractGBPPricesUnfiltered(html)
	}
	itemRe := regexp.MustCompile(`(?is)<li[^>]*class="[^"]*s-item[^"]*"[^>]*>(.*?)</li>`)
	items := itemRe.FindAllStringSubmatch(html, -1)
	if len(items) == 0 {
		return extractGBPPricesUnfiltered(html)
	}

	priceRe := regexp.MustCompile(`£\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?)`)
	setRe := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(setCode) + `\b`)
	var prices []float64
	for _, item := range items {
		segment := item[1]
		if !setRe.MatchString(segment) {
			continue
		}
		match := priceRe.FindStringSubmatch(segment)
		if len(match) < 2 {
			continue
		}
		value := strings.ReplaceAll(match[1], ",", "")
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		if parsed <= 0 || parsed > 5000 {
			continue
		}
		prices = append(prices, parsed)
	}

	if len(prices) == 0 {
		return extractGBPPricesUnfiltered(html)
	}
	return prices
}

func extractGBPPricesUnfiltered(html string) []float64 {
	priceRe := regexp.MustCompile(`£\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?)`)
	matches := priceRe.FindAllStringSubmatch(html, -1)
	prices := make([]float64, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.ReplaceAll(match[1], ",", "")
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		if parsed <= 0 || parsed > 5000 {
			continue
		}
		prices = append(prices, parsed)
	}
	return prices
}

func trimOutliers(values []float64, ratio float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	trim := int(math.Round(float64(len(values)) * ratio))
	if trim*2 >= len(values) {
		return values
	}
	return values[trim : len(values)-trim]
}

func summarizePrices(values []float64) (float64, float64, float64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	min := values[0]
	max := values[len(values)-1]
	var sum float64
	for _, value := range values {
		sum += value
		if value < min {
			min = value
		}
		if value > max {
			max = value
		}
	}
	avg := sum / float64(len(values))
	return avg, min, max
}
