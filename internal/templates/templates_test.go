package templates

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/matthewgall/blocks/internal/models"
)

type templateFixture struct {
	Name        *string
	Count       *int
	Price       *float64
	OccurredAt  *time.Time
	OccurredRaw time.Time
}

func TestValueOrEmpty(t *testing.T) {
	if got := valueOrEmpty(nil); got != "" {
		t.Fatalf("expected empty string for nil, got %q", got)
	}

	name := "Sample"
	if got := valueOrEmpty(&name); got != "Sample" {
		t.Fatalf("expected name, got %q", got)
	}

	count := 12
	if got := valueOrEmpty(&count); got != "12" {
		t.Fatalf("expected count, got %q", got)
	}

	price := 9.5
	if got := valueOrEmpty(&price); got != "9.5" {
		t.Fatalf("expected price, got %q", got)
	}

	date := time.Date(2024, time.March, 2, 15, 4, 5, 0, time.UTC)
	if got := valueOrEmpty(&date); got != "2024-03-02" {
		t.Fatalf("expected date, got %q", got)
	}
}

func TestTemplateValueFuncAvoidsNil(t *testing.T) {
	tmpl := template.New("test").Funcs(templateFuncs())
	parsed, err := tmpl.Parse(`{{value .Name}}|{{value .Count}}|{{value .Price}}|{{value .OccurredAt}}|{{value .OccurredRaw}}`)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	fixture := templateFixture{}
	var buf bytes.Buffer
	if err := parsed.Execute(&buf, fixture); err != nil {
		t.Fatalf("execute template: %v", err)
	}

	if got := buf.String(); got != "||||" {
		t.Fatalf("expected empty fields, got %q", got)
	}
}

func TestFormActionsUseCreateWhenIDZero(t *testing.T) {
	templates, err := LoadTemplates()
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	tests := []struct {
		name        string
		template    string
		data        map[string]interface{}
		expected    string
		notExpected string
	}{
		{
			name:     "brand form create",
			template: "brand_form.html",
			data: map[string]interface{}{
				"Title": "New Brand",
				"Brand": &models.Brand{},
				"role":  "admin",
			},
			expected:    "action=\"/brands\"",
			notExpected: "action=\"/brands/",
		},
		{
			name:     "set form create",
			template: "set_form.html",
			data: map[string]interface{}{
				"Title":       "New Set",
				"Set":         &models.Set{},
				"TagInput":    "",
				"Brands":      []models.Brand{},
				"CurrentYear": time.Now().Year(),
				"role":        "admin",
			},
			expected:    "action=\"/sets\"",
			notExpected: "action=\"/sets/",
		},
		{
			name:     "collection form create",
			template: "collection_form.html",
			data: map[string]interface{}{
				"Title":    "New Item",
				"Item":     &models.CollectionItem{},
				"TagInput": "",
				"Sets":     []models.Set{},
				"role":     "admin",
			},
			expected:    "action=\"/collection\"",
			notExpected: "action=\"/collection/",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpl, ok := templates[test.template]
			if !ok {
				t.Fatalf("missing template %s", test.template)
			}

			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, test.data); err != nil {
				t.Fatalf("execute template: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, test.expected) {
				t.Fatalf("expected %q in output", test.expected)
			}
			if strings.Contains(output, test.notExpected) && strings.Contains(output, test.expected) {
				t.Fatalf("did not expect %q in output", test.notExpected)
			}
		})
	}
}
