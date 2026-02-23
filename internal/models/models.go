package models

import (
	"database/sql/driver"
	"fmt"
	"time"
)

type BrandKind string

const (
	BrandKindLEGO    BrandKind = "lego"
	BrandKindClone   BrandKind = "clone"
	BrandKindGeneric BrandKind = "generic"
)

type ItemCondition string

const (
	ConditionSealed  ItemCondition = "sealed"
	ConditionOpen    ItemCondition = "open"
	ConditionPartial ItemCondition = "partial"
	ConditionCustom  ItemCondition = "custom"
)

type ItemStatus string

const (
	StatusActive  ItemStatus = "active"
	StatusSold    ItemStatus = "sold"
	StatusDonated ItemStatus = "donated"
)

type Provider string

const (
	ProviderManual              Provider = "manual"
	ProviderBrickset            Provider = "brickset"
	ProviderRebrickable         Provider = "rebrickable"
	ProviderBrickLink           Provider = "bricklink"
	ProviderExternalBrickset    Provider = "external_brickset"
	ProviderExternalRebrickable Provider = "external_rebrickable"
)

// UserRole defines the access level for a user.
type UserRole string

const (
	RoleAdmin  UserRole = "admin"
	RoleEditor UserRole = "editor"
	RoleViewer UserRole = "viewer"
)

func (b BrandKind) Valid() bool {
	return b == BrandKindLEGO || b == BrandKindClone || b == BrandKindGeneric
}

func (b BrandKind) String() string {
	return string(b)
}

func (i ItemCondition) Valid() bool {
	return i == ConditionSealed || i == ConditionOpen || i == ConditionPartial || i == ConditionCustom
}

func (i ItemCondition) String() string {
	return string(i)
}

func (i ItemStatus) Valid() bool {
	return i == StatusActive || i == StatusSold || i == StatusDonated
}

func (i ItemStatus) String() string {
	return string(i)
}

func (p Provider) Valid() bool {
	return p == ProviderManual || p == ProviderBrickset || p == ProviderRebrickable || p == ProviderBrickLink
}

func (p Provider) String() string {
	return string(p)
}

// Valid reports whether the role is recognized.
func (r UserRole) Valid() bool {
	return r == RoleAdmin || r == RoleEditor || r == RoleViewer
}

// String returns the string value for the role.
func (r UserRole) String() string {
	return string(r)
}

func (b BrandKind) Value() (driver.Value, error) {
	if !b.Valid() {
		return nil, fmt.Errorf("invalid brand kind: %s", b)
	}
	return b.String(), nil
}

func (b *BrandKind) Scan(value interface{}) error {
	if value == nil {
		*b = BrandKindGeneric
		return nil
	}

	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot scan %T into BrandKind", value)
	}

	kind := BrandKind(str)
	if !kind.Valid() {
		return fmt.Errorf("invalid brand kind: %s", str)
	}

	*b = kind
	return nil
}

type Brand struct {
	ID        int64     `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Kind      BrandKind `json:"kind" db:"kind"`
	Notes     *string   `json:"notes,omitempty" db:"notes"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type Set struct {
	ID         int64     `json:"id" db:"id"`
	BrandID    int64     `json:"brand_id" db:"brand_id"`
	SetCode    string    `json:"set_code" db:"set_code"`
	Name       string    `json:"name" db:"name"`
	Year       *int      `json:"year,omitempty" db:"year"`
	PieceCount *int      `json:"piece_count,omitempty" db:"piece_count"`
	Minifigs   *int      `json:"minifigs,omitempty" db:"minifigs"`
	Theme      *string   `json:"theme,omitempty" db:"theme"`
	ImageURL   *string   `json:"image_url,omitempty" db:"image_url"`
	Notes      *string   `json:"notes,omitempty" db:"notes"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`

	Brand           *Brand            `json:"brand,omitempty" db:"-"`
	CollectionItems []*CollectionItem `json:"collection_items,omitempty" db:"-"`
	Tags            []string          `json:"tags,omitempty" db:"-"`
}

type CollectionItem struct {
	ID            int64         `json:"id" db:"id"`
	SetID         int64         `json:"set_id" db:"set_id"`
	Quantity      int           `json:"quantity" db:"quantity"`
	Condition     ItemCondition `json:"condition" db:"condition"`
	Location      *string       `json:"location,omitempty" db:"location"`
	PurchasePrice *float64      `json:"purchase_price,omitempty" db:"purchase_price"`
	PurchaseDate  *time.Time    `json:"purchase_date,omitempty" db:"purchase_date"`
	MissingNotes  *string       `json:"missing_notes,omitempty" db:"missing_notes"`
	Status        ItemStatus    `json:"status" db:"status"`
	CreatedAt     time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at" db:"updated_at"`

	Set    *Set                  `json:"set,omitempty" db:"-"`
	Tags   []string              `json:"tags,omitempty" db:"-"`
	Images []CollectionItemImage `json:"images,omitempty" db:"-"`
}

type CollectionItemImage struct {
	ID               int64     `json:"id" db:"id"`
	CollectionItemID int64     `json:"collection_item_id" db:"collection_item_id"`
	StorageKey       string    `json:"storage_key" db:"storage_key"`
	ContentType      string    `json:"content_type" db:"content_type"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`

	PublicURL *string `json:"public_url,omitempty" db:"-"`
}

type Valuation struct {
	ID         int64          `json:"id" db:"id"`
	SetID      int64          `json:"set_id" db:"set_id"`
	Provider   Provider       `json:"provider" db:"provider"`
	Currency   string         `json:"currency" db:"currency"`
	Condition  *ItemCondition `json:"condition,omitempty" db:"condition"`
	Metric     *string        `json:"metric,omitempty" db:"metric"`
	Value      float64        `json:"value" db:"value"`
	SampleSize *int           `json:"sample_size,omitempty" db:"sample_size"`
	Confidence *int           `json:"confidence,omitempty" db:"confidence"`
	AsOfDate   time.Time      `json:"as_of_date" db:"as_of_date"`
	RawJSON    *string        `json:"raw_json,omitempty" db:"raw_json"`
	CreatedAt  time.Time      `json:"created_at" db:"created_at"`

	Set *Set `json:"set,omitempty" db:"-"`
}

type ExternalCache struct {
	ID          int64     `json:"id" db:"id"`
	Provider    Provider  `json:"provider" db:"provider"`
	CacheKey    string    `json:"cache_key" db:"cache_key"`
	PayloadJSON string    `json:"payload_json" db:"payload_json"`
	ETag        *string   `json:"etag,omitempty" db:"etag"`
	FetchedAt   time.Time `json:"fetched_at" db:"fetched_at"`
	TTLSeconds  int       `json:"ttl_seconds" db:"ttl_seconds"`
}

type User struct {
	ID                      int64      `json:"id" db:"id"`
	Username                string     `json:"username" db:"username"`
	PasswordHash            string     `json:"-" db:"password_hash"`
	Role                    UserRole   `json:"role" db:"role"`
	PublicCollectionEnabled bool       `json:"public_collection_enabled" db:"public_collection_enabled"`
	DisabledAt              *time.Time `json:"disabled_at,omitempty" db:"disabled_at"`
	CreatedAt               time.Time  `json:"created_at" db:"created_at"`
}
