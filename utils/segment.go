package utils

type SegmentEventInterface interface {
	SegmentEvent(name string, upn string)
}

func SegmentEventUserLogin(user string) {
	cfg.Segment.SegmentEvent("User Login", user)
}

func SegmentEventUserClientLogin(user string) {
	cfg.Segment.SegmentEvent("User Login VPN Client", user)
}

func SegmentEventUserVPNConnectionLogin(user string) {
	cfg.Segment.SegmentEvent("User Login VPN Connection", user)
}

func SegmentEventServerVPNConnectionLogin(upn string) {
	cfg.Segment.SegmentEvent("Server Login VPN Connection", upn)
}
