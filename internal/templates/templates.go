package templates

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

//go:embed views/*.html forms/*.html fragments/*.html
var templateFS embed.FS

func LoadTemplates() (map[string]*template.Template, error) {
	return LoadTemplatesFS(templateFS)
}

func LoadTemplatesFS(source fs.FS) (map[string]*template.Template, error) {
	layoutData, err := fs.ReadFile(source, "fragments/layout.html")
	if err != nil {
		return nil, err
	}

	fragmentFiles := []string{
		"fragments/csrf_input.html",
		"fragments/tag_input.html",
		"fragments/flash.html",
		"fragments/confirm_modal.html",
		"fragments/set_image.html",
		"fragments/collection_images.html",
	}

	templates := make(map[string]*template.Template)
	pageDirs := []string{"views", "forms"}
	for _, dir := range pageDirs {
		files, err := fs.ReadDir(source, dir)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}

			name := file.Name()
			if len(name) < 5 || name[len(name)-5:] != ".html" {
				continue
			}

			pageData, err := fs.ReadFile(source, dir+"/"+name)
			if err != nil {
				return nil, err
			}

			base := template.New("layout.html").Funcs(templateFuncs())
			if _, err := base.Parse(string(layoutData)); err != nil {
				return nil, err
			}
			for _, fragment := range fragmentFiles {
				fragmentData, err := fs.ReadFile(source, fragment)
				if err != nil {
					return nil, err
				}
				if _, err := base.Parse(string(fragmentData)); err != nil {
					return nil, err
				}
			}

			pageTemplate, err := base.Clone()
			if err != nil {
				return nil, err
			}

			if _, err := pageTemplate.New(name).Parse(string(pageData)); err != nil {
				return nil, err
			}

			templates[name] = pageTemplate
		}
	}

	return templates, nil
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"value":             valueOrEmpty,
		"dict":              dict,
		"setCodeWithSuffix": setCodeWithSuffix,
		"formatMoney":       formatMoney,
		"formatDate":        formatDate,
	}
}

func valueOrEmpty(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case *string:
		if typed == nil {
			return ""
		}
		return *typed
	case int:
		return strconv.Itoa(typed)
	case *int:
		if typed == nil {
			return ""
		}
		return strconv.Itoa(*typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case *int64:
		if typed == nil {
			return ""
		}
		return strconv.FormatInt(*typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case *float64:
		if typed == nil {
			return ""
		}
		return strconv.FormatFloat(*typed, 'f', -1, 64)
	case time.Time:
		if typed.IsZero() {
			return ""
		}
		return typed.Format("2006-01-02")
	case *time.Time:
		if typed == nil {
			return ""
		}
		if typed.IsZero() {
			return ""
		}
		return typed.Format("2006-01-02")
	default:
		return fmt.Sprintf("%v", value)
	}
}

func dict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict expects even number of arguments")
	}

	data := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		data[key] = values[i+1]
	}

	return data, nil
}

func setCodeWithSuffix(code string) string {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "-") {
		return trimmed
	}
	return trimmed + "-1"
}

func formatMoney(currency string, value interface{}) string {
	amount, ok := normalizeFloat(value)
	if !ok {
		return ""
	}
	currency = strings.TrimSpace(currency)
	if currency == "" {
		return fmt.Sprintf("%.2f", amount)
	}
	symbol := currencySymbol(currency)
	if symbol != "" {
		return fmt.Sprintf("%s%.2f", symbol, amount)
	}
	return fmt.Sprintf("%s %.2f", currency, amount)
}

func formatDate(value interface{}) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return ""
		}
		return typed.Format("Jan 2, 2006")
	case *time.Time:
		if typed == nil || typed.IsZero() {
			return ""
		}
		return typed.Format("Jan 2, 2006")
	default:
		return ""
	}
}

func normalizeFloat(value interface{}) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case *float64:
		if typed == nil {
			return 0, false
		}
		return *typed, true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case *int:
		if typed == nil {
			return 0, false
		}
		return float64(*typed), true
	case *int64:
		if typed == nil {
			return 0, false
		}
		return float64(*typed), true
	default:
		return 0, false
	}
}

func currencySymbol(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "GBP":
		return "£"
	case "USD":
		return "$"
	case "EUR":
		return "€"
	case "CAD":
		return "$"
	case "AUD":
		return "$"
	case "JPY":
		return "¥"
	default:
		return ""
	}
}
