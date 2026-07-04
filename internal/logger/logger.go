package logger

import (
	"log/slog"
	"os"
)

const (
	Debug = 0
	Info  = 1
	Warn  = 2
	Error = 3
)

var toSlog = map[int]slog.Level{
	Debug: slog.LevelDebug,
	Info:  slog.LevelInfo,
	Warn:  slog.LevelWarn,
	Error: slog.LevelError,
}

type NeutrinoLogger struct {
	logger   *slog.Logger
	logLevel slog.Level
}

type NeutrinoLoggerConfig struct {
	output *os.File
	level  int
}

// NewNeutrinoLogger returns a logger writing to stdout
func NewNeutrinoLogger(level int) *slog.Logger {
	out := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: toSlog[level],
		}))

	slog.SetDefault(out)

	return out
}

// TODO: Add options to make this configurable by reading the passed-in file path
// NewNeutrinoLoggerFromConfig creates a new logger from a JSON configuration on disk
func NewNeutrinoLoggerFromConfig(path string) *slog.Logger {
	level := toSlog[Info]

	out := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		}))

	slog.SetDefault(out)

	return out
}
