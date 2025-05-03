package config

import (
	"os"

	"github.com/sirupsen/logrus"
)

// setup logs with logrus

var Log *logrus.Logger

func InitLogger() {
	Log = logrus.New()
	Log.Out = os.Stdout
	Log.SetLevel(logrus.InfoLevel)
}

// func GetLogger(ctx context.Context) *logrus.Entry {
// 	logger, ok := ctx.Value("logger").(*logrus.Entry)
// 	if !ok {
// 		return Log.WithFields(logrus.Fields{
// 			"appName": "AuthServer",
// 			"env":     "development",
// 			"version": "1.0.0",
// 			"host":    "localhost",
// 		})
// 	}
// 	return logger
// }
