package bricklinkscrape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/models"
	"golang.org/x/net/html"
)

type Client struct {
	httpClient *http.Client
	cache      cache.Cache
}

type SetInfo struct {
	SetNumber string `json:"set_number"`
	Name      string `json:"name"`
	Theme     string `json:"theme"`
	Year      int    `json:"year"`
	Pieces    int    `json:"pieces"`
	ImageURL  string `json:"image_url"`
}

func New(cache cache.Cache) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
	}
}

func (c *Client) GetSetByNumber(ctx context.Context, setNumber string) (*SetInfo, error) {
	setNumber = normalizeSetCode(setNumber)
	if setNumber == "" {
		return nil, fmt.Errorf("set number required")
	}

	cacheKey := fmt.Sprintf("scrape:set:%s", setNumber)
	cached, err := c.cache.Get(ctx, models.ProviderBrickLink, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("checking cache: %w", err)
	}
	if cached != nil {
		var result SetInfo
		if err := json.Unmarshal([]byte(cached.PayloadJSON), &result); err != nil {
			return nil, fmt.Errorf("unmarshaling cached result: %w", err)
		}
		return &result, nil
	}

	url := fmt.Sprintf("https://www.bricklink.com/v2/catalog/catalogitem.page?S=%s", setNumber)
	root, err := c.fetchHTML(ctx, url)
	if err != nil {
		return nil, err
	}

	text := strings.Join(strings.Fields(nodeText(root)), " ")
	name, _ := extractTitle(root)
	result := &SetInfo{
		SetNumber: setNumber,
		Name:      name,
		Theme:     extractTheme(root),
		Year:      extractYear(text),
		Pieces:    extractPieceCount(text),
		ImageURL:  bricklinkImageURL(setNumber),
	}

	if err := c.cache.Set(ctx, models.ProviderBrickLink, cacheKey, result, 7*24*time.Hour, nil); err != nil {
		log.Printf("Warning: failed to cache BrickLink scrape for %s: %v", setNumber, err)
	}

	return result, nil
}

func (c *Client) fetchHTML(ctx context.Context, url string) (*html.Node, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Blocks/bricklink-scrape")
	req.Header.Set("Accept", "text/html")

	// #nosec G704 -- request targets a fixed bricklink domain.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bricklink page: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("closing bricklink scrape response: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bricklink request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	root, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse html: %w", err)
	}

	return root, nil
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

func bricklinkImageURL(setNumber string) string {
	if setNumber == "" {
		return ""
	}
	return fmt.Sprintf("https://img.bricklink.com/ItemImage/SN/0/%s.png", setNumber)
}

func extractTitle(root *html.Node) (string, error) {
	h1 := findFirstElement(root, "h1")
	if h1 == nil {
		return "", errors.New("no h1 title found")
	}
	return strings.TrimSpace(nodeText(h1)), nil
}

func extractTheme(root *html.Node) string {
	return strings.TrimSpace(findThemeText(root))
}

func extractYear(text string) int {
	for _, pattern := range []string{
		`(?i)Year Released:\s*(\d{4})`,
		`(?i)Released:\s*(\d{4})`,
	} {
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(text)
		if len(match) >= 2 {
			return parseInt(match[1])
		}
	}

	re := regexp.MustCompile(`\b(19|20)\d{2}\b`)
	match := re.FindString(text)
	if match == "" {
		return 0
	}
	return parseInt(match)
}

func extractPieceCount(text string) int {
	for _, pattern := range []string{
		`\b(\d[\d,]*)\s*Parts?\b`,
		`\b(\d[\d,]*)\s*Pieces?\b`,
	} {
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(text)
		if len(match) >= 2 {
			return parseInt(match[1])
		}
	}
	return 0
}

func findFirstElement(node *html.Node, tag string) *html.Node {
	if node.Type == html.ElementNode && strings.EqualFold(node.Data, tag) {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findFirstElement(child, tag); found != nil {
			return found
		}
	}
	return nil
}

func nodeText(node *html.Node) string {
	if node == nil {
		return ""
	}
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			builder.WriteString(n.Data)
			builder.WriteString(" ")
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}

func findThemeText(node *html.Node) string {
	if node.Type == html.ElementNode && strings.EqualFold(node.Data, "a") {
		for _, attr := range node.Attr {
			if strings.EqualFold(attr.Key, "href") && strings.Contains(attr.Val, "catalogList.asp?catType=S&catString=") {
				return nodeText(node)
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if text := findThemeText(child); strings.TrimSpace(text) != "" {
			return text
		}
	}
	return ""
}

func parseInt(value string) int {
	cleaned := strings.ReplaceAll(value, ",", "")
	var parsed int
	_, _ = fmt.Sscanf(cleaned, "%d", &parsed)
	return parsed
}
