package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/ncert"
	"gorm.io/gorm"
)

func CreateCertAccess(db *gorm.DB, acc *Access, publickey string) (Certificate, error) {
	var mycert Certificate
	var err error

	var dest Entity

	if result := db.
		First(&dest, "id = ?", acc.EntityID); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return mycert, fmt.Errorf("cannot create certificate - entity not found, id: %d", acc.EntityID)
		} else {
			return mycert, result.Error
		}
	}

	var Myregex = `([^a-zA-Z0-9])`
	var re = regexp.MustCompile(Myregex)
	s := re.ReplaceAllString(acc.Name, "_")
	if s != "" {
		s = ":" + s
	}

	mycert, err = CreateCert(db, acc, dest.UPN+s, []string{}, publickey)
	return mycert, err
}

func CreateCert(db *gorm.DB, acc *Access, certname string, subnets []string, publickey string) (Certificate, error) {
	grpsid := []string{"0"}
	for _, g := range acc.AccessGroups {
		grpsid = append(grpsid, fmt.Sprint(g.GroupID))
	}

	var dbgrps []Group
	if err := db.Where("id IN (" + strings.Join(grpsid, ",") + ")").Find(&dbgrps).Error; err != nil {
		return Certificate{}, err
	}

	grps := []string{}
	for _, g := range dbgrps {
		grps = append(grps, g.Name)
	}

	ipcidr := acc.IpAddress + SystemConfig().GetCIDRMask()

	tn := time.Now().UTC()
	dur := int(acc.ValidTo.UTC().Sub(tn).Seconds())
	if dur <= 0 {
		return Certificate{}, errors.New("Time ValidTo is smaller than current time.")
	}

	nc, ncstr, err := ncert.GenerateCert(certname, dur, strings.Join(grps, ","), ipcidr, subnets, publickey)

	cert := Certificate{
		AccessID:        acc.ID,
		Metadata:        ncstr,
		SecretCrt:       nc.Crt,
		SecretKey:       nc.Key,
		SecretPublicKey: publickey,
		Fingerprint:     nc.Certinfo.Fingerprint,
		ValidFrom:       nc.Certinfo.Details.Notbefore,
		ValidTo:         nc.Certinfo.Details.Notafter,
	}

	return cert, err
}
