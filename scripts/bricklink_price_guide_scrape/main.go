package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type priceGuideResult struct {
	SetCode          string `json:"set_code"`
	SourceURL        string `json:"source_url"`
	ItemID           int    `json:"item_id"`
	InventoryAvgNew  string `json:"inventory_avg_new"`
	InventoryAvgUsed string `json:"inventory_avg_used"`
	Currency         string `json:"currency"`
	Warning          string `json:"warning,omitempty"`
}

type inventoryResponse struct {
	List []inventoryItem `json:"list"`
}

type inventoryItem struct {
	CodeNew          string `json:"codeNew"`
	DisplaySalePrice string `json:"mDisplaySalePrice"`
	Quantity         int    `json:"n4Qty"`
}

func main() {
	setCode := flag.String("set", "", "LEGO set code (e.g., 10311-1)")
	source := flag.String("source", "priceguide", "Source page: priceguide or catalog")
	flag.Parse()

	code := strings.TrimSpace(*setCode)
	if code == "" {
		fmt.Fprintln(os.Stderr, "set code is required")
		os.Exit(1)
	}

	result, err := scrapeBrickLinkPriceGuide(code, *source)
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

func scrapeBrickLinkPriceGuide(setCode string, source string) (*priceGuideResult, error) {
	page := strings.ToLower(strings.TrimSpace(source))
	url := fmt.Sprintf("https://www.bricklink.com/catalogPG.asp?S=%s", setCode)
	if page == "catalog" {
		url = fmt.Sprintf("https://www.bricklink.com/v2/catalog/catalogitem.page?S=%s#T=P", setCode)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bricklink page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bricklink request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	content := string(body)
	root, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("parse html: %w", err)
	}

	result := &priceGuideResult{SetCode: setCode, SourceURL: url}
	result.Currency = extractCurrency(content)

	_ = root

	itemID := extractItemID(content)
	if itemID > 0 {
		result.ItemID = itemID
		inventoryURL := fmt.Sprintf("https://www.bricklink.com/ajax/clone/catalogifs.ajax?itemid=%d&iconly=0", itemID)
		inventoryData, err := fetchInventory(inventoryURL)
		if err == nil {
			newAvg, usedAvg, currency := summarizeInventory(inventoryData)
			result.InventoryAvgNew = newAvg
			result.InventoryAvgUsed = usedAvg
			if currency != "" {
				result.Currency = currency
			}
		} else if result.Warning == "" {
			result.Warning = "inventory data unavailable"
		}
	}
	if result.InventoryAvgNew == "" && result.InventoryAvgUsed == "" && result.Warning == "" {
		result.Warning = "no inventory pricing found"
	}
	if result.Currency == "" {
		result.Currency = detectCurrency(result.InventoryAvgNew, result.InventoryAvgUsed)
	}

	return result, nil
}

func extractCurrency(html string) string {
	re := regexp.MustCompile(`(?is)prices in[^\(]*\(([^)]+)\)`)
	match := re.FindStringSubmatch(html)
	if len(match) >= 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func splitPriceGuideColumns(root *html.Node) (*html.Node, *html.Node, *html.Node, *html.Node) {
	row := findPriceGuideRow(root)
	if row == nil {
		return nil, nil, nil, nil
	}
	var cells []*html.Node
	for child := row.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode && strings.EqualFold(child.Data, "td") {
			if strings.EqualFold(getAttr(child, "valign"), "top") {
				cells = append(cells, child)
			}
		}
	}
	if len(cells) < 4 {
		return nil, nil, nil, nil
	}
	return cells[0], cells[1], cells[2], cells[3]
}

func extractLabelInt(node *html.Node, label string) int {
	value := extractLabelString(node, label)
	return parseInt(value)
}

func extractLabelString(node *html.Node, label string) string {
	if node == nil {
		return ""
	}
	labelLower := strings.ToLower(label)
	var value string
	walk(node, func(n *html.Node) bool {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "tr") {
			cells := rowCells(n)
			if len(cells) < 2 {
				return false
			}
			labelText := strings.ToLower(strings.TrimSpace(nodeText(cells[0])))
			if strings.HasPrefix(labelText, strings.ToLower(labelLower)) {
				valueText := strings.TrimSpace(nodeText(cells[1]))
				value = strings.TrimSpace(stripLabelArtifacts(valueText))
				return true
			}
		}
		return false
	})
	return value
}

func findPriceGuideRow(root *html.Node) *html.Node {
	var row *html.Node
	walk(root, func(n *html.Node) bool {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "tr") {
			if strings.EqualFold(getAttr(n, "bgcolor"), "#C0C0C0") {
				row = n
				return true
			}
		}
		return false
	})
	return row
}

func findFirstElement(node *html.Node, tag string) *html.Node {
	var found *html.Node
	walk(node, func(n *html.Node) bool {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, tag) {
			found = n
			return true
		}
		return false
	})
	return found
}

func nodeText(node *html.Node) string {
	if node == nil {
		return ""
	}
	var builder strings.Builder
	walk(node, func(n *html.Node) bool {
		if n.Type == html.TextNode {
			builder.WriteString(n.Data)
			builder.WriteString(" ")
		}
		return false
	})
	return builder.String()
}

func rowCells(row *html.Node) []*html.Node {
	var cells []*html.Node
	for child := row.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode && strings.EqualFold(child.Data, "td") {
			cells = append(cells, child)
		}
	}
	return cells
}

func stripLabelArtifacts(value string) string {
	value = strings.ReplaceAll(value, "\u00a0", " ")
	return strings.TrimSpace(value)
}

func detectCurrency(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "US $") || strings.HasPrefix(upper, "USD"):
			return "USD"
		case strings.HasPrefix(upper, "GBP") || strings.Contains(trimmed, "£"):
			return "GBP"
		case strings.HasPrefix(upper, "EUR") || strings.Contains(trimmed, "€"):
			return "EUR"
		}
	}
	return ""
}

func extractItemID(html string) int {
	re := regexp.MustCompile(`itemID=(\d+)`)
	match := re.FindStringSubmatch(html)
	if len(match) >= 2 {
		return parseInt(match[1])
	}
	return 0
}

func fetchInventory(url string) (*inventoryResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
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

func summarizeInventory(response *inventoryResponse) (string, string, string) {
	if response == nil {
		return "", "", ""
	}
	var newPrices []float64
	var usedPrices []float64
	var currency string
	for _, item := range response.List {
		price := parseCurrencyAmount(item.DisplaySalePrice)
		if price <= 0 {
			continue
		}
		currency = detectCurrency(item.DisplaySalePrice, currency)
		if strings.EqualFold(item.CodeNew, "N") {
			newPrices = append(newPrices, price)
		} else if strings.EqualFold(item.CodeNew, "U") {
			usedPrices = append(usedPrices, price)
		}
	}
	return formatAverage(newPrices), formatAverage(usedPrices), currency
}

func parseCurrencyAmount(value string) float64 {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return 0
	}
	clean = strings.ReplaceAll(clean, "GBP", "")
	clean = strings.ReplaceAll(clean, "US $", "")
	clean = strings.ReplaceAll(clean, "CA $", "")
	clean = strings.ReplaceAll(clean, "EUR", "")
	clean = strings.ReplaceAll(clean, "£", "")
	clean = strings.ReplaceAll(clean, "€", "")
	clean = strings.ReplaceAll(clean, ",", "")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func formatAverage(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	var sum float64
	for _, value := range values {
		sum += value
	}
	avg := sum / float64(len(values))
	return fmt.Sprintf("%.2f", avg)
}

func walk(node *html.Node, visitor func(*html.Node) bool) bool {
	if visitor(node) {
		return true
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if walk(child, visitor) {
			return true
		}
	}
	return false
}

func getAttr(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, key) {
			return strings.TrimSpace(attr.Val)
		}
	}
	return ""
}

func parseInt(value string) int {
	clean := strings.ReplaceAll(value, ",", "")
	clean = strings.ReplaceAll(clean, "£", "")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return 0
	}
	var parsed int
	_, _ = fmt.Sscanf(clean, "%d", &parsed)
	return parsed
}
