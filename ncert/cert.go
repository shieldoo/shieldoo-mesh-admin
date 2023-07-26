package ncert

import "time"

type NebulaCertificateInfo struct {
	Details struct {
		Groups    []string      `json:"groups"`
		Ips       []string      `json:"ips"`
		Isca      bool          `json:"isCa"`
		Issuer    string        `json:"issuer"`
		Name      string        `json:"name"`
		Notafter  time.Time     `json:"notAfter"`
		Notbefore time.Time     `json:"notBefore"`
		Publickey string        `json:"publicKey"`
		Subnets   []interface{} `json:"subnets"`
	} `json:"details"`
	Fingerprint string `json:"fingerprint"`
	Signature   string `json:"signature"`
}

type NebulaCertificate struct {
	Certinfo NebulaCertificateInfo
	Crt      string
	Key      string
}
