package main

import (
	"github.com/jmoiron/sqlx"
	httpSwagger "github.com/swaggo/http-swagger"
	"log"
	"net/http"
	"test_task/api/handler"
	_ "test_task/docs"
	"test_task/repository"
	"test_task/service"
)

// @title			TestTask
// @version		1.0
// @termsOfService	http://swagger.io/terms/
func main() {
	db, err := sqlx.Open("postgres", "postgres://admin:admin@task_db:5432/taskdb?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	sessionRepo := repository.NewSessionRepository(db)
	userRepo := repository.NewUserRepository(db)

	userSerivce := service.NewUserService(*userRepo)
	authService := service.NewAuthService(*userRepo)
	authHanlder := handler.NewAuthHandler(*userSerivce, *authService, *sessionRepo)

	authRouter := http.NewServeMux()
	authRouter.HandleFunc("POST /register", authHanlder.RegisterUser)
	authRouter.HandleFunc("POST /login", authHanlder.LoginUser)
	authRouter.HandleFunc("POST /renew", authHanlder.RenewAccessToken)
	authRouter.HandleFunc("GET /swagger/", httpSwagger.WrapHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: authRouter,
	}
	log.Println("server started")
	server.ListenAndServe()
}
