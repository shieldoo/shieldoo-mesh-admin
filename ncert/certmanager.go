package ncert

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	log "github.com/sirupsen/logrus"
)

var caCert string = ""
var caKey string = ""

func getCaCert() (string, error) {
	if caCert != "" {
		return caCert, nil
	}
	buf, err := ioutil.ReadFile("ca/ca.crt")
	if err != nil {
		return "", nil
	}
	caCert = string(buf)
	return caCert, nil
}

func getCaKey() (string, error) {
	if caKey != "" {
		return caKey, nil
	}
	buf, err := ioutil.ReadFile("ca/ca.key")
	if err != nil {
		return "", nil
	}
	caKey = string(buf)
	return caKey, nil
}

/*
	"Usage of "+os.Args[0]+" sign <flags>: create and sign a certificate\n"+
		"  -ca-crt string\n"+
		"    \tOptional: path to the signing CA cert (default \"ca.crt\")\n"+
		"  -ca-key string\n"+
		"    \tOptional: path to the signing CA key (default \"ca.key\")\n"+
		"  -duration duration\n"+
		"    \tOptional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"\n"+
		"  -groups string\n"+
		"    \tOptional: comma separated list of groups\n"+
		"  -in-pub string\n"+
		"    \tOptional (if out-key not set): path to read a previously generated public key\n"+
		"  -ip string\n"+
		"    \tRequired: ip and network in CIDR notation to assign the cert\n"+
		"  -name string\n"+
		"    \tRequired: name of the cert, usually a hostname\n"+
		"  -out-crt string\n"+
		"    \tOptional: path to write the certificate to\n"+
		"  -out-key string\n"+
		"    \tOptional (if in-pub not set): path to write the private key to\n"+
		"  -out-qr string\n"+
		"    \tOptional: output a qr code image (png) of the certificate\n"+
		"  -subnets string\n"+
		"    \tOptional: comma separated list of subnet this cert can serve for\n",
*/

func nebulaPrint(incert string) (NebulaCertificateInfo, string, error) {
	var c *cert.NebulaCertificate
	var rawCert []byte
	var err error
	rawCert = []byte(incert)
	// get only first cert from data
	c, _, err = cert.UnmarshalNebulaCertificateFromPEM(rawCert)
	if err != nil {
		return NebulaCertificateInfo{}, "", err
	}
	b, _ := json.Marshal(c)
	ret := NebulaCertificateInfo{}
	jerr := json.Unmarshal(b, &ret)
	if jerr != nil {
		log.Error("JSON error: ", jerr)
		return NebulaCertificateInfo{}, "", jerr
	}
	return ret, string(b), nil
}

func GetCACert() (NebulaCertificateInfo, string, error) {
	c, err := getCaCert()
	if err != nil {
		log.Fatal("cannot load CA certificate", err)
		return NebulaCertificateInfo{}, "", err
	}
	ci, _, err := nebulaPrint(c)
	return ci, c, err
}

func nebulax25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}

// create client key/crt and sign, returning in order:
// - key
// - crt
// - error
func nebulaSign(name string, durationSeconds int, groups string, ipCIDR string, subnets []string, publickey string) (string, string, error) {
	rawCAKey, err := getCaKey()
	if err != nil {
		log.Error("error while reading ca-key: ", err)
		return "", "", err
	}
	caKey, _, err := cert.UnmarshalEd25519PrivateKey([]byte(rawCAKey))
	if err != nil {
		log.Error("error while parsing ca-key: ", err)
		return "", "", err
	}
	rawCACert, err := getCaCert()
	if err != nil {
		log.Error("error while reading ca-crt: ", err)
		return "", "", err
	}
	caCert, _, err := cert.UnmarshalNebulaCertificateFromPEM([]byte(rawCACert))
	if err != nil {
		log.Error("error while parsing ca-crt: ", err)
		return "", "", err
	}
	if err := caCert.VerifyPrivateKey(cert.Curve_CURVE25519, caKey); err != nil {
		log.Error("refusing to sign, root certificate does not match private key")
		return "", "", errors.New("refusing to sign, root certificate does not match private key")
	}
	issuer, err := caCert.Sha256Sum()
	if err != nil {
		log.Error("error while getting -ca-crt fingerprint: ", err)
		return "", "", err
	}
	if caCert.Expired(time.Now().UTC()) {
		log.Error("ca certificate is expired")
		return "", "", errors.New("ca certificate is expired")
	}
	// if no duration is given, expire one second before the root expires
	_duration := time.Duration(durationSeconds) * time.Second
	if durationSeconds <= 0 {
		_duration = time.Until(caCert.Details.NotAfter) - time.Second*1
	}
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		log.Error("invalid ip definition: ", err)
		return "", "", err
	}
	ipNet.IP = ip
	_groups := []string{}
	if groups != "" {
		for _, rg := range strings.Split(groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				_groups = append(_groups, g)
			}
		}
	}
	subn := []*net.IPNet{}
	for _, rs := range subnets {
		if rs != "" {
			_, s, err := net.ParseCIDR(rs)
			if err != nil {
				log.Error("invalid subnet definition: ", err)
				return "", "", err
			}
			if s.IP.To4() == nil {
				log.Error("invalid subnet definition: can only be ipv4, have ", rs)
				return "", "", err
			}
			subn = append(subn, s)
		}
	}
	var pub, rawPriv []byte
	var privKey string
	if publickey == "" {
		pub, rawPriv = nebulax25519Keypair()
		privKey = string(cert.MarshalX25519PrivateKey(rawPriv))
	} else {
		privKey = ""
		if _pubKey, _, err := cert.UnmarshalX25519PublicKey([]byte(publickey)); err != nil {
			log.Error("client public key has wrong format: ", err)
			return "", "", err
		} else {
			pub = _pubKey
		}
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      name,
			Ips:       []*net.IPNet{ipNet},
			Groups:    _groups,
			Subnets:   subn,
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().UTC().Add(_duration),
			PublicKey: pub,
			IsCA:      false,
			Issuer:    issuer,
		},
	}

	if err := nc.CheckRootConstrains(caCert); err != nil {
		log.Error("refusing to sign, root certificate constraints violated: ", err)
		return "", "", err
	}
	err = nc.Sign(cert.Curve_CURVE25519, caKey)
	if err != nil {
		log.Error("error while signing: ", err)
		return "", "", err
	}
	b, err := nc.MarshalToPEM()
	if err != nil {
		log.Error("error while marshalling certificate: ", err)
		return "", "", err
	}
	return privKey, string(b), nil
}

func GenerateCert(name string, durationSeconds int, groups string, ipCIDR string, subnets []string, publickey string) (NebulaCertificate, string, error) {
	log.Debug("generating certificate: ", name)
	log.Debug("generating certificate, public key: ", publickey)
	var c NebulaCertificate

	// generate certificate
	key, crt, err := nebulaSign(name, durationSeconds, groups, ipCIDR, subnets, publickey)
	if err != nil {
		log.Error("error nebula sign(): ", err)
		return c, "", err
	}

	// convert certificate to json
	ci, crtjson, err := nebulaPrint(crt)
	if err != nil {
		log.Error("error nebula print(): ", err)
		return c, "", err
	}

	c.Certinfo = ci
	c.Crt = crt
	c.Key = key

	log.Debug("NebulaCert: ", c)

	return c, crtjson, nil
}
