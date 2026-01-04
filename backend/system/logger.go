package system

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel represents logging severity
type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelWarn
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides file-based logging with rotation
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	logger   *log.Logger
	logDir   string
	filename string
	date     string
}

// Global logger instance
var globalLogger *Logger

// InitLogger initializes the global logger
func InitLogger(logDir string) error {
	if logDir == "" {
		logDir = "./logs"
	}

	// Create log directory if not exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	globalLogger = &Logger{
		logDir:   logDir,
		filename: "kg-proxy.log",
	}

	if err := globalLogger.rotateIfNeeded(); err != nil {
		return err
	}

	return nil
}

// rotateIfNeeded checks if log rotation is needed (daily)
func (l *Logger) rotateIfNeeded() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if l.date == today && l.file != nil {
		return nil
	}

	// Close old file
	if l.file != nil {
		l.file.Close()
	}

	// Create new log file with date suffix
	logPath := filepath.Join(l.logDir, fmt.Sprintf("kg-proxy-%s.log", today))
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Also write to stdout for systemd journal
	multi := io.MultiWriter(os.Stdout, file)

	l.file = file
	l.logger = log.New(multi, "", 0)
	l.date = today

	return nil
}

// Log writes a log entry
func (l *Logger) Log(level LogLevel, format string, args ...interface{}) {
	if l == nil || l.logger == nil {
		// Fallback to standard log if logger not initialized
		log.Printf("[%s] %s", level.String(), fmt.Sprintf(format, args...))
		return
	}

	_ = l.rotateIfNeeded()

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-04 15:04:05")
	message := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s] %s", timestamp, level.String(), message)
}

// Package-level logging functions

// Info logs an info message
func Info(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(LevelInfo, format, args...)
	} else {
		log.Printf("[INFO] "+format, args...)
	}
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(LevelWarn, format, args...)
	} else {
		log.Printf("[WARN] "+format, args...)
	}
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Log(LevelError, format, args...)
	} else {
		log.Printf("[ERROR] "+format, args...)
	}
}

// Close closes the logger
func Close() {
	if globalLogger != nil && globalLogger.file != nil {
		globalLogger.file.Close()
	}
}
