package models

import "time"

// CountryGroup represents a named collection of countries for easier management
type CountryGroup struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"unique;not null" json:"name"`
	Description string    `json:"description"`
	Countries   string    `gorm:"type:text" json:"countries"` // Comma-separated ISO codes: "CN,RU,KP"
	Color       string    `json:"color"`                      // UI tag color (hex or name)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
