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

var jwtKey = []byte(os.Getenv("SECRET"))

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

func (manager *JWTManager) Verify(accessToken string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(
        accessToken,
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

func unaryInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    log.Println("--> unary interceptor: ", info.FullMethod)
    return handler(ctx, req)
}

func streamInterceptor(
    srv interface{},
    stream grpc.ServerStream,
    info *grpc.StreamServerInfo,
    handler grpc.StreamHandler,
) error {
    log.Println("--> stream interceptor: ", info.FullMethod)
    return handler(srv, stream)
}

func main() {
	flag.Parse()
	database.ConnectDB()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)
	pb.RegisterUserServer(s, &server{})

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Parse JWT, find user and return user
func (s *server) Restore(ctx context.Context, in *pb.RestoreUserRequest) (*pb.RestoreUserResponse, error)  {
	token := in.GetToken()
	claims := &Claims{}
	jwtManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)

	claims, err := jwtManager.Verify(token)

	db := database.DB
	id := claims.UserID

	var user model.User
	db.First(&user, id)

	if (user.ID == 0) {
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
		return &pb.RestoreUserResponse{}, nil
	}

	return &pb.RestoreUserResponse{token: tokenString, user: &pb.DbUser{id: safeUser.ID, username: safeUser.Username, email: safeUser.Email, description: safeUser.Description, online: safeUser.Online}}, nil
}

// Login get user and password
func (s *server) Login(ctx context.Context, in *pb.LoginUserRequest) (*pb.LoginUserResponse, error) {
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

	input = LoginInput{
		Email: in.GetEmail(),
		Password: in.GetPassword(),
	}

	db := database.DB
	email := input.Email
	pass := input.Password

	user := db.Where(&model.User{Email: email}).First(&model.User{})

	if user == nil {
		return &pb.LoginUserResponse{}, nil
	}

	ud = UserData{
		ID:       user.ID,
		Email:    user.Email,
		Password: user.Password,
	}

	if !CheckPasswordHash(pass, ud.Password) {
		return &pb.LoginUserResponse{}, nil
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Email: ud.Email,
		UserID: string(ud.ID),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return &pb.LoginUserResponse{}, nil
	}

	user.Online = true
	db.Save(&user)

	safeUser := SafeUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}

	return &pb.LoginUserResponse{token: tokenString, user: &pb.DbUser{id: safeUser.ID, username: safeUser.Username, email: safeUser.Email, description: safeUser.Description, online: safeUser.Online}}, nil
}

// Signup create user, return cookie and user
func (s* server) Signup(ctx context.Context, in *pb.SignupUserRequest) (*pb.SignupUserResponse, error) {
	user := new(model.User)

	user.Username = in.GetUsername()
	user.Email = in.GetEmail()
	user.Password = in.GetPassword()
	user.Description = in.GetDescription()
	user.Online = true

	db := database.DB

	if err := db.Create(user).Error; err != nil {
		return &pb.SignupUserResponse{}, nil
	}

	if err := db.Where(&model.User{Email: user.Email}).First(&model.User{}).Error; err == nil {
		return &pb.SignupUserResponse{}, nil
	}

	if err := db.Where(&model.User{Username: user.Username}).First(&model.User{}).Error; err == nil {
		return &pb.SignupUserResponse{}, nil
	}

	hash, err := HashPassword(user.Password)
	if err != nil {
		return &pb.SignupUserResponse{}, nil
	}

	user.Password = hash
	if err := db.Create(&user).Error; err != nil {
		return &pb.SignupUserResponse{}, nil
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Email: user.Email,
		UserID: string(user.ID),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return &pb.SignupUserResponse{}, nil
	}

	safeUser := SafeUser{
		ID:       string(user.ID),
		Username: user.Username,
		Email:    user.Email,
		Description: user.Description,
		Online: user.Online,
	}

	return &pb.SignupUserResponse{Token: tokenString, User: &pb.DbUser{Id: safeUser.ID, Username: safeUser.Username, Email: safeUser.Email, Description: safeUser.Description, Online: safeUser.Online}}, nil
}

func (s *server) Logout(ctx context.Context, in *pb.LogoutUserRequest) (*pb.LogoutUserResponse, error) {
	userId := in.GetId()
	db := database.DB
	token := in.GetToken()
	jwtManager := NewJWTManager(os.Getenv("SECRET"), 15*time.Minute)

	claims, err := jwtManager.Verify(token)

	if err != nil {
		return &pb.LogoutUserResponse{}, nil
	}

	if claims.UserID != userId {
		return &pb.LogoutUserResponse{}, nil
	}

	id, err := strconv.ParseUint(userId, 10, 64)

	if err != nil {
		return &pb.LogoutUserResponse{}, nil
	}

	user := db.Where(&model.User{ID: uint(id)}).First(&model.User{})
	if user == nil {
		return &pb.LogoutUserResponse{}, nil
	}

	user.Online = false
	db.Save(&user)

	return &pb.LogoutUserResponse{message: "Logout successful"}, nil
}
