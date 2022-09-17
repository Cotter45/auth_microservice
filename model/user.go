package model

import "gorm.io/gorm"

// User struct
type User struct {
	gorm.Model
	ID 		 uint   `json:"id"`
	Username string `gorm:"unique_index;not null" json:"username"`
	Email    string `gorm:"unique_index;not null" json:"email"`
	Password string `gorm:"not null" json:"password"`
	Description string `json:"description"`
	Online bool `json:"online"`
}