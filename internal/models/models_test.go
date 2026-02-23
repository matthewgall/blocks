package models

import (
	"testing"
)

func TestBrandKind_Valid(t *testing.T) {
	tests := []struct {
		name string
		kind BrandKind
		want bool
	}{
		{"valid lego", BrandKindLEGO, true},
		{"valid clone", BrandKindClone, true},
		{"valid generic", BrandKindGeneric, true},
		{"invalid", BrandKind("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.Valid(); got != tt.want {
				t.Errorf("BrandKind.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestItemCondition_Valid(t *testing.T) {
	tests := []struct {
		name      string
		condition ItemCondition
		want      bool
	}{
		{"valid sealed", ConditionSealed, true},
		{"valid open", ConditionOpen, true},
		{"valid partial", ConditionPartial, true},
		{"valid custom", ConditionCustom, true},
		{"invalid", ItemCondition("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.condition.Valid(); got != tt.want {
				t.Errorf("ItemCondition.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestItemStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status ItemStatus
		want   bool
	}{
		{"valid active", StatusActive, true},
		{"valid sold", StatusSold, true},
		{"valid donated", StatusDonated, true},
		{"invalid", ItemStatus("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("ItemStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBrandKind_Scan(t *testing.T) {
	tests := []struct {
		name      string
		value     interface{}
		want      BrandKind
		wantError bool
	}{
		{"valid lego", "lego", BrandKindLEGO, false},
		{"valid clone", "clone", BrandKindClone, false},
		{"valid generic", "generic", BrandKindGeneric, false},
		{"nil", nil, BrandKindGeneric, false},
		{"invalid", "invalid", BrandKind(""), true},
		{"wrong type", 123, BrandKind(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b BrandKind
			var err error

			if tt.value == nil {
				err = b.Scan(nil)
			} else {
				err = b.Scan(tt.value)
			}

			if (err != nil) != tt.wantError {
				t.Errorf("BrandKind.Scan() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && b != tt.want {
				t.Errorf("BrandKind.Scan() = %v, want %v", b, tt.want)
			}
		})
	}
}
