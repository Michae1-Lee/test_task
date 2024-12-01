# Используем официальный образ Go
FROM golang:latest

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы go.mod и go.sum
COPY go.mod go.sum ./

# Загружаем зависимости
RUN go mod download

# Копируем остальной исходный код
COPY . .

# Собираем приложение
RUN go build -o test_task ./cmd/main.go

# Указываем команду для запуска приложения
CMD ["./test_task"]
