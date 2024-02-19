package log

import (
	"github.com/doraemonkeys/mylog"
	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger
var NoConsole bool
var LoggerLevel string

func NewLoggerG() {
	cnf := mylog.LogConfig{}
	// cnf.ErrSeparate = true
	cnf.LogDir = "./calog"
	cnf.NoConsole = NoConsole
	cnf.MaxKeepDays = 30
	cnf.LogLevel = LoggerLevel
	cnf.ShowShortFileInConsole = true
	cnf.DisableWriterBuffer = true
	cnf.DateSplit = true
	cnf.DisableLevelTruncation = true
	cnf.PadLevelText = true
	logger, err := mylog.NewLogger(cnf)
	if err != nil {
		panic(err)
	}
	Logger = logger
}
