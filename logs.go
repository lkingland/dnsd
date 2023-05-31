package dnsd

import "github.com/rs/zerolog"

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(DefaultLogLevel)
}

type logLevel zerolog.Level

const (
	LogDebug    = zerolog.DebugLevel
	LogInfo     = zerolog.InfoLevel
	LogWarn     = zerolog.WarnLevel
	LogDisabled = zerolog.Disabled
)

// SetLogLevel to LogDebug, LogInfo, LogWarn, or LogDisabled
// Errors are always returned as values.
func SetLogLevel(l logLevel) {
	zerolog.SetGlobalLevel(zerolog.Level(l))
}
