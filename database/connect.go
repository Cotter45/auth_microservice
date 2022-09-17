package database

import (
	"fmt"
	"github.com/Cotter45/auth_microservice/model"

	"gorm.io/driver/sqlite"
	// "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ConnectDB connect to db
func ConnectDB() {
	var err error
	if err != nil {
		fmt.Println(err)
	}
	DB, err = gorm.Open(
		sqlite.Open("database/user.db"), 
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent), PrepareStmt: true,
			})

	if err != nil {
		panic("failed to connect database")
	}
		
	// db, err := DB.DB()
	// db.SetMaxIdleConns(100)
	// db.SetMaxOpenConns(200)

	// DB, err = gorm.Open(
	// 	postgres.Open("host=localhost user=postgres password=postgres dbname=postgres port=8080 sslmode=disable"),
	// 	&gorm.Config{
	// 		Logger: logger.Default.LogMode(logger.Silent), PrepareStmt: true,
	// 	})

	if err != nil {
		panic("failed to connect database")
	}

	fmt.Println("Connection Opened to Database")
	DB.AutoMigrate(&model.User{})
	fmt.Println("Database Migrated")
}