package utils

var breakAADWaitLoop bool = true

func BreakAADWaitLoop() {
	breakAADWaitLoop = true
}

func SetAADWaitLoop() {
	breakAADWaitLoop = false
}

func GetBreakAADWaitLoop() bool {
	return breakAADWaitLoop
}
