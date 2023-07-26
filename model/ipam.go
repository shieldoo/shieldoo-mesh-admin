package model

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/apparentlymart/go-cidr/cidr"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type IpamNamedArgument struct {
	Till  int
	Start int
}

type IpamError struct {
	message string
}

func (ipame *IpamError) Error() string {
	return ipame.message
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// AcquireIP new ip for specific config
func AcquireIP(db *gorm.DB, acc *Access, ip net.IP, withLock bool) (Ipam, error) {
	log.Debug(fmt.Sprintf("Acquiring IP: %v", ip))
	var ipam Ipam
	var ipAsNumber int
	_, actualcidr, _ := net.ParseCIDR(SystemConfig().GetCIDR())
	lighthouseCount := SystemConfig().GetMaxLighthouses()
	networkIp, broadcastIp := cidr.AddressRange(actualcidr)
	firtsLightHouse := ipamGetHost(actualcidr, 1)
	lastLightHouse := ipamGetHost(actualcidr, lighthouseCount)
	log.Debug(fmt.Sprintf("Network: %v, Broadcast: %v, first lighthouse IP : %v, last lighthouse: %v", networkIp, broadcastIp, firtsLightHouse, lastLightHouse))

	start := ipNumberInCidr(*actualcidr, lastLightHouse)
	till := ipNumberInCidr(*actualcidr, broadcastIp) - 1 //do not offer broadcast as free ip
	if ip == nil {
		// lock table ipams
		if withLock {
			if ret := db.Exec("LOCK TABLE ipams IN ACCESS EXCLUSIVE MODE"); ret.Error != nil {
				return Ipam{}, ret.Error
			}
		}
		log.Debug("Looking up free address")
		ipAsNumber = getNextFreeIpNumber(db, start, till)
		if ipAsNumber == 0 {
			return Ipam{}, &IpamError{message: fmt.Sprintf("CIDR: %s depleted", actualcidr.String())}
		}
	} else {
		log.Debug("Verifying IP")

		if !actualcidr.Contains(ip) {
			return Ipam{}, &IpamError{message: fmt.Sprintf("IP: %s is not part of assigned CIDR: %s", ip.String(), actualcidr.String())}
		} else {
			if broadcastIp.Equal(ip) || networkIp.Equal(ip) {
				return Ipam{}, &IpamError{message: fmt.Sprintf("IP: %s is network IP or broadcast IP", ip.String())}
			}
			if IpBetween(firtsLightHouse, lastLightHouse, ip) {
				return Ipam{}, &IpamError{message: fmt.Sprintf("IP: %s conflicts with reserved Lighthouses range(%s - %s) in assigned CIDR: %s", ip.String(), firtsLightHouse.String(), lastLightHouse.String(), actualcidr.String())}
			}

		}
		ipAsNumber = ipNumberInCidr(*actualcidr, ip)
		isFree := isIpFree(db, int(ipAsNumber))
		if !isFree {
			return Ipam{}, &IpamError{message: fmt.Sprintf("IP: %s is not free", ip.String())}
		}
	}

	acquiredIp, _ := cidr.Host(actualcidr, ipAsNumber)
	fmt.Println(acquiredIp)
	newIpam := Ipam{IPNumber: ipAsNumber, IP: acquiredIp.String()}

	fmt.Println(newIpam)
	db.Create(&newIpam)
	acc.IpAddress = acquiredIp.String()
	return ipam, nil
}

func ipamGetHost(base *net.IPNet, num int) net.IP {
	ip, err := cidr.Host(base, num)
	if err != nil {
		panic(err)
	}
	return ip
}
func isIpFree(db *gorm.DB, ipNumber int) bool {
	var count int64
	db.Debug().Model(&Ipam{}).Where("ip_number = ?", ipNumber).Count(&count)
	return int(count) == 0
}

func ipNumberInCidr(cidr net.IPNet, ip net.IP) int {
	return int(ip2int(ip) - ip2int(cidr.IP))
}

func getNextFreeIpNumber(db *gorm.DB, start int, till int) int {
	params := IpamNamedArgument{Start: start, Till: till}
	var ipAsNumber int
	db.Raw("SELECT MIN(ip_number) + 1  "+
		" FROM ( SELECT ip_number"+
		"        FROM ipams "+
		"        WHERE ip_number BETWEEN @Start AND @Till "+
		"        UNION  "+
		"       SELECT @Start ) tmp "+
		" WHERE NOT EXISTS ( SELECT NULL "+
		"                    FROM ipams "+
		"                    WHERE ip_number = tmp.ip_number + 1 ) "+
		" group by tmp.ip_number "+
		" having "+
		"	tmp.ip_number < @Till"+
		" limit 1", params).Find(&ipAsNumber)
	return ipAsNumber
}

func IpBetween(from net.IP, to net.IP, test net.IP) bool {
	if from == nil || to == nil || test == nil {
		return false
	}

	from16 := from.To16()
	to16 := to.To16()
	test16 := test.To16()
	if from16 == nil || to16 == nil || test16 == nil {
		return false
	}

	if bytes.Compare(test16, from16) >= 0 && bytes.Compare(test16, to16) <= 0 {
		return true
	}
	return false
}

func ip2int(ip net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(ip.To4())
	return IPv4Int.Int64()
}

// canonicalize a CIDR block: make sure none of the host bits are set
func canonicalize(cidr string) string {
	// dotted-decimal / bits in network part
	split := strings.Split(cidr, "/")
	dotted := split[0]
	size, err := strconv.Atoi(split[1])
	check(err)

	// get IP as binary string
	var bin []string
	for _, n := range strings.Split(dotted, ".") {
		i, err := strconv.Atoi(n)
		check(err)
		bin = append(bin, fmt.Sprintf("%08b", i))
	}
	binary := strings.Join(bin, "")

	// replace the host part with all zeros
	binary = binary[0:size] + strings.Repeat("0", 32-size)

	// convert back to dotted-decimal
	var canon []string
	for i := 0; i < len(binary); i += 8 {
		num, err := strconv.ParseInt(binary[i:i+8], 2, 64)
		check(err)
		canon = append(canon, fmt.Sprintf("%d", num))
	}

	// and return
	return strings.Join(canon, ".") + "/" + split[1]
}
