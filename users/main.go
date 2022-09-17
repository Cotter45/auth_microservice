package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
	"os"

	"github.com/Cotter45/auth_microservice/users/database"
	"github.com/Cotter45/auth_microservice/users/model"
	pb "github.com/Cotter45/auth_microservice/users/proto"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type Claims struct {
	Email string `json:"email"`
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

type SafeUser struct {
	ID       string   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Description string `json:"description"`
	Online bool `json:"online"`
}

type server struct {
	pb.UnimplementedUserServer
}

type JWTManager struct {
    secretKey     string
    tokenDuration time.Duration
}

func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
    return &JWTManager{secretKey, tokenDuration}
}

func (manager *JWTManager) Generate(user *SafeUser) (string, error) {
    claims := Claims{
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(manager.tokenDuration).Unix(),
        },
        UserID: user.ID,
        Email:     user.Email,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(manager.secretKey))
}

func (manager *JWTManager) Verify(accessToken []byte) (*Claims, error) {

    token, err := jwt.ParseWithClaims(
        string(accessToken),
        &Claims{},
        func(token *jwt.Token) (interface{}, error) {
            _, ok := token.Method.(*jwt.SigningMethodHMAC)
            if !ok {
                return nil, fmt.Errorf("unexpected token signing method")
            }

            return []byte(manager.secretKey), nil
        },
    )

    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    claims, ok := token.Claims.(*Claims)
    if !ok {
        return nil, fmt.Errorf("invalid token claims")
    }

    return claims, nil
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
func (s *server) RestoreUser(ctx context.Context, in *pb.RestoreUserRequest) (*pb.RestoreUserResponse, error)  {
	token := in.GetToken()
	jwtManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)

	claims, err := jwtManager.Verify(token)

	if err != nil {
		log.Println("Error verifying token")
		return &pb.RestoreUserResponse{}, nil
	}

	db := database.DB
	id := claims.UserID

	var user model.User
	db.First(&user, id)

	if (user.ID == 0) {
		log.Println("User not found")
		return &pb.RestoreUserResponse{}, nil
	}

	if (!user.Online) {
		log.Println("User is not online")
		return &pb.RestoreUserResponse{}, nil
	}

	userID := strconv.FormatUint(uint64(user.ID), 10)

	safeUser := SafeUser{
		ID:       userID,
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}

	newToken, err := jwtManager.Generate(&safeUser)

	if err != nil {
		log.Println(err, "Error generating token")
		return nil, err
	}

	return &pb.RestoreUserResponse{Token: []byte(newToken), User: &pb.DbUser{
		Id: userID,
		Username: user.Username,
		Email: user.Email,
		Description: user.Description,
		Online: user.Online,
	}}, nil
}

// Login get user and password
func (s *server) LoginUser(ctx context.Context, in *pb.LoginUserRequest) (*pb.LoginUserResponse, error) {
	email := in.GetEmail()
	password := in.GetPassword()

	db := database.DB

	user := model.User{}
	db.Where("email = ?", email).First(&user)

	if (user.ID == 0) {
		log.Println("User not found")
		return &pb.LoginUserResponse{}, nil
	}

	if !CheckPasswordHash(password, user.Password) {
		log.Println("Wrong password")
		return &pb.LoginUserResponse{}, nil
	}

	if (user.Online) {
		log.Println("User already online")
		return &pb.LoginUserResponse{}, nil
	}

	user.Online = true
	db.Save(&user)

	safeUser := SafeUser{
		ID:       fmt.Sprint(user.ID),
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}

	JWTManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)
	accessToken, err := JWTManager.Generate(&safeUser)

	if err != nil {
		log.Println("Error generating token")
		return &pb.LoginUserResponse{}, nil
	}

	return &pb.LoginUserResponse{Token: []byte(accessToken), User: &pb.DbUser{
		Id: safeUser.ID,
		Username: safeUser.Username,
		Email: safeUser.Email,
		Description: safeUser.Description,
		Online: safeUser.Online,
	}}, nil
}

// Signup create user, return cookie and user
func (s* server) SignupUser(ctx context.Context, in *pb.SignupUserRequest) (*pb.SignupUserResponse, error) {
	user := new(model.User)

	user.Username = in.GetUsername()
	user.Email = in.GetEmail()
	user.Password = in.GetPassword()
	user.Description = in.GetDescription()
	user.Online = true

	db := database.DB

	if err := db.Where(&model.User{Email: user.Email}).First(&model.User{}).Error; err == nil {
		log.Println(err, "User already exists")
		return &pb.SignupUserResponse{}, nil
	}

	if err := db.Where(&model.User{Username: user.Username}).First(&model.User{}).Error; err == nil {
		log.Println(err, "User already exists")
		return &pb.SignupUserResponse{}, nil
	}

	hash, err := HashPassword(user.Password)
	if err != nil {
		log.Println(err, "Error hashing password")
		return &pb.SignupUserResponse{}, nil
	}

	user.Password = hash
	if err := db.Create(&user).Error; err != nil {
		log.Println(err, "Error creating user")
		return &pb.SignupUserResponse{}, nil
	}

	safeUser := SafeUser{
		ID:       fmt.Sprint(user.ID),
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}


	JWTManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)
	accessToken, err := JWTManager.Generate(&safeUser)

	if err != nil {
		return &pb.SignupUserResponse{}, nil
	}

	return &pb.SignupUserResponse{Token: []byte(accessToken), User: &pb.DbUser{Id: safeUser.ID, Username: safeUser.Username, Email: safeUser.Email, Description: safeUser.Description, Online: safeUser.Online}}, nil
}

func (s *server) LogoutUser(ctx context.Context, in *pb.LogoutUserRequest) (*pb.LogoutUserResponse, error) {
	db := database.DB
	token := in.GetToken()
	jwtManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)

	claims, err := jwtManager.Verify(token)

	if err != nil {
		log.Println(err, "Error verifying token")
		return &pb.LogoutUserResponse{}, nil
	}

	claim := Claims{
		UserID: claims.UserID,
	}

	id := claim.UserID
	var user model.User
	db.First(&user, id)
	if user.ID == 0 {
		log.Println("User not found")
		return &pb.LogoutUserResponse{}, nil
	}
	
	user.Online = false
	db.Save(&user)

	return &pb.LogoutUserResponse{Message: "Success"}, nil
}
