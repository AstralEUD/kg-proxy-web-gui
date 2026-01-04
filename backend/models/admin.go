package models

import (
	"time"
)

type Admin struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	Username          string     `gorm:"unique;not null" json:"username"`
	Password          string     `gorm:"not null" json:"-"` // Stored hashed
	CreatedAt         time.Time  `json:"created_at"`
	FailedAttempts    int        `gorm:"default:0" json:"-"`
	LastFailedAttempt *time.Time `json:"-"`
	LockedUntil       *time.Time `json:"-"`
}

// SystemSettings for Security Levels
type SecuritySettings struct {
	ID               uint   `gorm:"primaryKey"`
	Level            string `gorm:"default:'standard'"` // standard, high, emergency
	AllowedCountries string `gorm:"default:'KR'"`       // CSV: KR,JP,US
}
