//go:build !bricklink
// +build !bricklink

package bricklink

import (
	"context"
	"fmt"
	"time"

	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/models"
)

type Client struct{}

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

func New(_ interface{}, _ cache.Cache) *Client {
	return &Client{}
}

func (c *Client) GetPriceGuide(ctx context.Context, setNumber string, condition models.ItemCondition, currency string) (*Valuation, error) {
	return nil, fmt.Errorf("bricklink API disabled; build with -tags=bricklink to enable")
}
