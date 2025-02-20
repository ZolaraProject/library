package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	ERR = iota
	WARN
	INFO
	DEBUG
)

var logLevels = map[string]int{
	"ERR":   ERR,
	"WARN":  WARN,
	"INFO":  INFO,
	"DEBUG": DEBUG,
}

var (
	level  string
	logger *log.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
)

func init() {
	var ok bool
	level, ok = os.LookupEnv("LOG_LEVEL")
	if !ok {
		logger.Println("LOG_LEVEL not set, defaulting to INFO")
		level = "INFO"
		return
	}

	level = strings.ToUpper(level)
	if _, ok := logLevels[level]; !ok {
		logger.Printf("Invalid log level: %s. Available log levels are ERROR, WARNING, INFO, DEBUG, TRACE. Using default log level INFO", level)
		level = "INFO"
		return
	}

	logger.Printf("Setting log level to %s", level)
}

func Err(grpcToken string, message string, args ...any) {
	if logLevels[level] >= ERR {
		logger.Printf(fmt.Sprintf("[%s] [ERR] %s", grpcToken, message), args...)
	}
}

func Warn(grpcToken string, message string, args ...any) {
	if logLevels[level] >= WARN {
		logger.Printf(fmt.Sprintf("[%s] [WARN] %s", grpcToken, message), args...)
	}
}

func Info(grpcToken string, message string, args ...any) {
	if logLevels[level] >= INFO {
		logger.Printf(fmt.Sprintf("[%s] [INFO] %s", grpcToken, message), args...)
	}
}

func Debug(grpcToken string, message string, args ...any) {
	if logLevels[level] >= DEBUG {
		logger.Printf(fmt.Sprintf("[%s] [DEBUG] %s", grpcToken, message), args...)
	}
}
