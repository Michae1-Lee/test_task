package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"test_task/api/types"
	"test_task/domain"
	"test_task/repository"
	"test_task/service"
	"time"
)

// AuthHandler отвечает за обработку всех запросов, связанных с авторизацией и регистрацией пользователей.
type AuthHandler struct {
	ctx         context.Context              // Контекст для операций с базой данных и другими сервисами
	userService service.UserService          // Сервис для работы с пользователями
	authService service.AuthService          // Сервис для создания и проверки токенов
	sessionRepo repository.SessionRepository // Репозиторий для работы с сессиями пользователей
}

// NewAuthHandler создает новый экземпляр AuthHandler.
func NewAuthHandler(userService service.UserService, authService service.AuthService, sessionRepo repository.SessionRepository) *AuthHandler {
	return &AuthHandler{
		ctx:         context.Background(), // Инициализация контекста
		userService: userService,          // Сервис для работы с пользователями
		authService: authService,          // Сервис для работы с токенами
		sessionRepo: sessionRepo,          // Репозиторий для сессий
	}
}

// RegisterUser обрабатывает запрос на регистрацию нового пользователя.
//
// @Summary Регистрация нового пользователя
// @Description Регистрирует нового пользователя с email и паролем.
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body types.RegisterRequest true "Registration details"
// @Success 201 {string} string "User created successfully"
// @Failure 400 {string} string "Bad request - validation error"
// @Failure 500 {string} string "Internal server error"
// @Router /register [post]
func (h *AuthHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	var req types.RegisterRequest
	// Декодирование запроса
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}

	id := uuid.New()

	// Создание нового пользователя
	err := h.userService.CreateNewUser(domain.User{Id: id.String(), Email: req.Email, Password: req.Password})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ответ с кодом 201, если пользователь создан
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created successfully"))
}

// LoginUser обрабатывает запрос на авторизацию пользователя.
//
// @Summary Авторизация пользователя
// @Description Аутентифицирует пользователя и возвращает access token и refresh token.
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param request body types.LoginReq true "Login credentials"
// @Success 200 {object} types.LoginResp "Login successful"
// @Failure 400 {string} string "Bad request - invalid credentials or other errors"
// @Failure 401 {string} string "Unauthorized - wrong password or invalid credentials"
// @Failure 500 {string} string "Internal server error"
// @Router /login [post]
func (h *AuthHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	var req types.LoginReq
	ip := r.RemoteAddr // Получаем IP-адрес клиента

	// Декодируем тело запроса
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Находим пользователя по email
	user, err := h.userService.Find(req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}

	// Генерируем access и refresh токены
	accessToken, accessClaims, err := h.authService.GenerateToken(user.Id, user.Email, ip, 15*time.Minute)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	refreshToken, refreshClaims, err := h.authService.GenerateToken(user.Id, user.Email, ip, 24*time.Hour)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Кодируем refresh токен в base64
	encodedRefreshToken := base64.URLEncoding.EncodeToString([]byte(refreshToken))

	// Хэшируем refresh токен для безопасности
	hash := sha256.Sum256([]byte(refreshToken))
	hashedRefreshToken, err := bcrypt.GenerateFromPassword(hash[:], bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Создаем сессию для пользователя
	session, err := h.sessionRepo.CreateSession(h.ctx, &domain.Session{
		Id:           refreshClaims.RegisteredClaims.ID,
		UserEmail:    user.Email,
		Ip:           ip,
		RefreshToken: string(hashedRefreshToken),
		AccessToken:  accessToken,
		ExpiresAt:    refreshClaims.RegisteredClaims.ExpiresAt.Time,
	})
	if err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	// Формируем ответ с токенами и информацией о пользователе
	resp := types.LoginResp{
		SessionId:             session.Id,
		AccessToken:           accessToken,
		RefreshToken:          encodedRefreshToken,
		AccessTokenExpiresAt:  accessClaims.RegisteredClaims.ExpiresAt.Time,
		RefreshTokenExpiresAt: refreshClaims.RegisteredClaims.ExpiresAt.Time,
		User:                  user,
	}

	// Отправляем ответ в формате JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// RenewAccessToken обновляет access token, используя refresh token.
//
// @Summary Обновление access token с использованием refresh token
// @Description Обновляет access token, если предоставлен действующий refresh token.
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param Authorization header string true "Authorization header with Bearer token\n Напишите сюда 'Bearer access_token'"
// @Param request body types.RenewAccessTokenReq true "Request with refresh token"
// @Success 200 {object} types.RenewAccessTokenResp "Access token successfully renewed"
// @Failure 400 {string} string "Bad request - invalid refresh token format"
// @Failure 401 {string} string "Unauthorized - invalid or expired refresh token"
// @Failure 500 {string} string "Internal server error"
// @Router /renew [post]
func (h *AuthHandler) RenewAccessToken(w http.ResponseWriter, r *http.Request) {
	var req types.RenewAccessTokenReq
	// Получаем заголовок Authorization
	header := r.Header.Get("Authorization")
	if header == "" {
		http.Error(w, "empty auth header", http.StatusUnauthorized)
		return
	}

	//Bearer <token>
	headersParts := strings.Split(header, " ")
	if len(headersParts) != 2 {
		http.Error(w, "invalid auth header", http.StatusUnauthorized)
		return
	}

	// Проверяем токен в заголовке
	_, err := h.authService.VerifyToken(headersParts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Декодируем тело запроса для получения refresh token
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "error decoding request body", http.StatusBadRequest)
		return
	}

	// Проверяем refresh token
	refreshClaims, err := h.authService.VerifyToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "error verifying refresh token", http.StatusUnauthorized)
		return
	}

	// Получаем сессию пользователя
	session, err := h.sessionRepo.GetSession(h.ctx, refreshClaims.RegisteredClaims.ID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if headersParts[1] != session.AccessToken {
		http.Error(w, "Refresh token does not match the access token", http.StatusUnauthorized)
		return
	}
	log.Println("tam")

	// Проверяем, соответствует ли email пользователя
	if session.UserEmail != refreshClaims.Email {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	// Проверяем, не изменился ли IP
	if session.Ip != refreshClaims.Ip {
		log.Println("your ip has changed")
	}

	// Генерируем новый access token
	accessToken, accessClaims, err := h.authService.GenerateToken(refreshClaims.ID, refreshClaims.Email, refreshClaims.Ip, 15*time.Minute)
	if err != nil {
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}

	// Формируем ответ с новым access token
	res := types.RenewAccessTokenResp{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessClaims.RegisteredClaims.ExpiresAt.Time,
	}

	// Отправляем ответ в формате JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}
