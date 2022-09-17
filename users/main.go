package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"go_grpc/users/database"
	"go_grpc/users/model"
	pb "go_grpc/users/proto"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

var jwtKey = []byte(config.Config("SECRET"))

type Claims struct {
	Email string `json:"email"`
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

type SafeUser struct {
	ID       string   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	ProfilePicture string `json:"profile_picture"`
	CoverPicture string `json:"cover_picture"`
	Description string `json:"description"`
	Online bool `json:"online"`
}

type server struct {
	pb.UnimplementedUserServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) GetUser(ctx context.Context, in *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	db := database.DB
	id := in.GetId()
	fmt.Println("ID: ", id)

	var user model.User
	db.First(&user, id)
	fmt.Println("User: ", user)
	// convert user.ID to string
	userID := strconv.FormatUint(uint64(user.ID), 10)

	return &pb.GetUserResponse{Email: user.Email, Username: user.Username, Id: userID}, nil
}

// CreateUser creates a new user
func (s *server) CreateUser(ctx context.Context, in *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	db := database.DB
	username := in.GetUsername()
	email := in.GetEmail()
	password := in.GetPassword()

	user := model.User{Username: username, Email: email, Password: password}
	db.Create(&user)

	return &pb.CreateUserResponse{Email: user.Email, Username: user.Username, Id: strconv.FormatUint(uint64(user.ID), 10)}, nil
}

// GetUsers returns all users
func (s *server) GetUsers(ctx context.Context, in *pb.GetUsersRequest) (*pb.GetUsersResponse, error) {
	db := database.DB
	var users []model.User
	db.Find(&users)

	var usersResponse []*pb.GetUserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, &pb.GetUserResponse{Email: user.Email, Username: user.Username, Id: strconv.FormatUint(uint64(user.ID), 10)})
	}

	return &pb.GetUsersResponse{Users: usersResponse}, nil
}

func main() {
	flag.Parse()
	database.ConnectDB()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Parse JWT, find user and return user
func (s *server) Restore(ctx context.Context, in *pb.RestoreTokenRequest) (*pb.RestoreTokenResponse, error)  {
	cookie := in.GetToken()
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if !token.Valid {
		return
	}

	db := database.DB
	id := in.GetId()

	var user model.User
	db.First(&user, id)

	userID := strconv.FormatUint(uint64(user.ID), 10)

	safeUser := SafeUser{
		ID:       userID,
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	newClaims := &Claims{
		Email: safeUser.Email,
		UserID: safeUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		return 
	}

	return safeUser, tokenString
}

// Login get user and password
func Login(c *fiber.Ctx) error {
	type LoginInput struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	type UserData struct {
		ID       uint   `json:"id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var input LoginInput
	var ud UserData

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Error on login request", "data": err})
	}
	identity := input.Email
	pass := input.Password

	user, err := GetUserByEmail(identity)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Error on email", "data": err})
	}

	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "User not found", "data": err})
	}

	ud = UserData{
		ID:       user.ID,
		Email:    user.Email,
		Password: user.Password,
	}

	if !CheckPasswordHash(pass, ud.Password) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid password", "data": nil})
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Email: ud.Email,
		UserID: ud.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error on login request", "data": err})
	}

	c.Cookie(&fiber.Cookie{
		Expires: expirationTime,
		Path:    "/",
		Secure:  config.Config("ENVIRONMENT") == "production",
		SameSite: "Lax",
		HTTPOnly: true,
		Value:  tokenString,
		Name:    "token",
	})

	user.Online = true
	config.DB.Save(&user)

	safeUser := SafeUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		ProfilePicture: user.ProfilePicture,
		CoverPicture: user.CoverPicture,
		Description: user.Description,
		Online: user.Online,
	}

	return c.JSON(fiber.Map{"status": "success", "message": "Success login", "data": safeUser})
}

// Signup create user, return cookie and user
func Signup(c *fiber.Ctx) error {
	user := new(models.User)

	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Error on signup request", "data": err})
	}

	email := user.Email
	pass := user.Password
	username := user.Username

	if err := config.DB.Where(&models.User{Email: email}).First(&models.User{}).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"status": "error", "message": "User already exists", "data": nil})
	}

	if err := config.DB.Where(&models.User{Username: username}).First(&models.User{}).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"status": "error", "message": "User already exists", "data": nil})
	}

	hash, err := HashPassword(pass)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Couln't hash password", "data": err})
	}

	user.Password = hash
	if err := config.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error on signup request", "data": err})
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Email: user.Email,
		UserID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error on login request", "data": err})
	}

	c.Cookie(&fiber.Cookie{
		Expires: expirationTime,
		Path:    "/",
		Secure:  config.Config("ENVIRONMENT") == "production",
		SameSite: "Lax",
		HTTPOnly: true,
		Value:  tokenString,
		Name:    "token",
	})
	
	user.Online = true
	config.DB.Save(&user)

	safeUser := SafeUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		ProfilePicture: user.ProfilePicture,
		CoverPicture: user.CoverPicture,
		Description: user.Description,
		Online: user.Online,
	}

	return c.JSON(fiber.Map{"status": "success", "message": "Success login", "data": safeUser})
}

// Logout delete cookie
func Logout(c *fiber.Ctx) error {
	cookie := c.Cookies("token")
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return c.Status(200).JSON(fiber.Map{"status": "error", "message": "Invalid token", "data": nil})
	}
	if !token.Valid {
		return c.Status(401).JSON(fiber.Map{"status": "error", "message": "Invalid token", "data": nil})
	}

	user, err := GetUserByEmail(claims.Email)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"status": "error", "message": "Invalid token", "data": nil})
	}

	user.Online = false
	config.DB.Save(&user)

	newCookie := new(fiber.Cookie)
	newCookie.Name = "token"
	newCookie.Expires = time.Now().AddDate(0, 0, -1)
	newCookie.Path = "/"
	newCookie.Secure = false
	newCookie.HTTPOnly = true
	c.Cookie(newCookie)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "Success logout", "data": nil})
}
