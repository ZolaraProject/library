package logger

import (
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
		logger.Printf("Invalid log level: %s", level)
		level = "INFO"
		return
	}

	logger.Printf("Setting log level to %s", level)
}

func Err(message string, args ...any) {
	if logLevels[level] >= ERR {
		logger.Printf(message, args...)
	}
}

func Warn(message string, args ...any) {
	if logLevels[level] >= WARN {
		logger.Printf(message, args...)
	}
}

func Info(message string, args ...any) {
	if logLevels[level] >= INFO {
		logger.Printf(message, args...)
	}
}

func Debug(message string, args ...any) {
	if logLevels[level] >= DEBUG {
		logger.Printf(message, args...)
	}
}
