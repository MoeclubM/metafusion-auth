package models

import (
    "time"
    "github.com/google/uuid"
)

type User struct {
    ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
    Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
    Email        string    `gorm:"size:255;uniqueIndex;not null" json:"email"`
    PasswordHash string    `gorm:"size:255;not null" json:"-"`
    Role         string    `gorm:"size:32;default:user" json:"role"`
    IsActive     bool      `gorm:"default:true" json:"is_active"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type OAuthClient struct {
    ClientID     string    `gorm:"size:64;primaryKey" json:"client_id"`
    ClientSecret string    `gorm:"size:255;not null" json:"-"`
    ClientName   string    `gorm:"size:128;not null" json:"client_name"`
    RedirectURIs string    `gorm:"type:text;not null" json:"redirect_uris"`
    Scopes       string    `gorm:"size:255;not null" json:"scopes"`
    CreatedAt    time.Time `json:"created_at"`
}
