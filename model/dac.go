package model

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"github.com/shieldoo/shieldoo-mesh-admin/myjwt"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Code list item.
type CodeListItem struct {
	// Numeric ID
	ID int `json:"id"`
	// Name of the record
	Name string `json:"name"`
}

// cost usage statistics
type CostUsageItem struct {
	// year+month
	YearMonth string
	// upn
	Upn string
	// is user
	IsUser bool
	// hours
	HoursUsed int
	// cost
	Cost float64
}

// month usage total statistics
type CostMonthTotalItem struct {
	// year+month
	YearMonth string
	// cost
	Cost float64
	// users and servers
	UsageItems []CostUsageItem
}

func DacGetCostUsage() (costMonthTotal []CostMonthTotalItem, err error) {
	db := Connection()
	var result *gorm.DB
	var costItems []CostUsageItem
	// 3 month back in format yyyyMM
	monthBack := time.Now().AddDate(0, -3, 0).Format("200601") + "0000"
	result = db.Raw(
		`select substring(hour_period, 1, 6) as year_month, upn, is_user, sum(contacted) as hours_used, 0.0 as cost from (
			select 1 as contacted, hour_period, upn, is_user from access_statistic_data asd 
			where is_connected = true and hour_period > ?
			group by hour_period, upn , is_user ) as stx
			group by upn, is_user, year_month
			order by year_month desc, is_user, upn`, monthBack).
		Scan(&costItems)
	if result.Error != nil {
		return nil, result.Error
	}
	// convert to month cost items and calculate price
	var currMonth string
	var currIndex int = -1
	for _, item := range costItems {
		if currMonth != item.YearMonth {
			currMonth = item.YearMonth
			currIndex++
			costMonthTotal = append(costMonthTotal, CostMonthTotalItem{
				YearMonth: currMonth,
				Cost:      0.0,
			})
		}
		item.Cost = float64(item.HoursUsed) * _cfg.CostManagement.HourPrice
		if item.Cost > _cfg.CostManagement.MonthPrice {
			item.Cost = _cfg.CostManagement.MonthPrice
		}
		costMonthTotal[currIndex].Cost += item.Cost
		costMonthTotal[currIndex].UsageItems = append(costMonthTotal[currIndex].UsageItems, item)
	}
	return
}

func DacSaveKey(key string, value string) error {
	db := Connection()
	kvdef := KeyValueStore{ID: key, Data: value, Changed: time.Now().UTC()}
	result := db.Save(&kvdef)
	return result.Error
}

func DacGetKey(key string) (string, error) {
	db := Connection()
	var kvdef KeyValueStore
	result := db.Where("id = ?", key).First(&kvdef)
	return kvdef.Data, result.Error
}

func dacCodeListgeneric(codelist string) (dest []CodeListItem, err error) {
	db := Connection()

	result := db.Raw("SELECT id, name FROM " + codelist + " ORDER BY name").Scan(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacCodeListGroups() (dest []CodeListItem, err error) {
	return dacCodeListgeneric("groups")
}

func DacCodeListFirewalls() (dest []CodeListItem, err error) {
	return dacCodeListgeneric("fwconfigs")
}

func DacCodeListUserAccessTemplates() (dest []CodeListItem, err error) {
	db := Connection()

	result := db.Raw("SELECT id, name FROM user_access_templates WHERE deleted=false ORDER BY name").Scan(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacAdminDashboardStats() (users int, servers int, usersInvited int, err error) {
	db := Connection()
	var result *gorm.DB
	result = db.Raw("SELECT count(*) FROM entities WHERE entity_type = 1").Scan(&users)
	if result.Error != nil {
		return 0, 0, 0, result.Error
	}
	result = db.Raw("SELECT count(*) FROM entities WHERE entity_type = 1 AND origin = 'invited'").Scan(&usersInvited)
	if result.Error != nil {
		return 0, 0, 0, result.Error
	}
	result = db.Raw("SELECT count(*) FROM entities WHERE entity_type = 0").Scan(&servers)
	if result.Error != nil {
		return 0, 0, 0, result.Error
	}
	return
}

type StatUsersInHour struct {
	Date  string
	Users int
}

func DacAdminDashboardStatsUsersInHours() (userstats []StatUsersInHour, err error) {
	t := time.Now().UTC()
	vals := ""
	for i := 0; i > -24; i-- {
		if i < 0 {
			vals += ","
		}
		vals += "('" + t.Add(time.Hour*time.Duration(i)).Format("2006010215") + "')"
	}
	db := Connection()
	result := db.Raw(`
	SELECT d.dhour as "date",
		count(case WHEN asd.id is NOT NULL THEN 1 end) as users
		FROM (values` + vals + `) AS d(dhour) left outer
		JOIN access_statistic_data asd
			ON asd.hour_period = d.dhour AND asd.is_user = true AND asd.is_connected = true
		GROUP BY  d.dhour
		ORDER BY  d.dhour`).Scan(&userstats)
	if result.Error != nil {
		return nil, result.Error
	}
	return
}

func DacCleanDeviceLog() {
	db := Connection()

	if result := db.Delete(DeviceLogin{}, "created < ?", time.Now().UTC().Add(time.Hour*(-1))); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
}

func DacCleanAccessStats() {
	db := Connection()
	t := time.Now().UTC().Add(time.Hour * (-(125 * 24)))
	st := t.Format("2006010215")
	if result := db.Delete(AccessStatisticData{}, "hour_period < ?", st); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
}

func dacGenericDelete(dest interface{}, id int, logupn string) (err error) {
	db := Connection()
	if result := db.Delete(dest, id); result.Error != nil {
		return dacProcessGormResult(result)
	} else if result.RowsAffected == 0 {
		return fmt.Errorf("No record found.")
	}
	return nil
}

func dacProcessGormResult(result *gorm.DB) error {
	ret := result.Error
	if ret != nil {
		ret = dacProcessError(ret)
	} else if result.RowsAffected == 0 {
		ret = fmt.Errorf("Not found")
	}
	return ret
}

func dacProcessError(ret error) error {
	if ret != nil {
		var pgError, ispg = ret.(*pgconn.PgError)
		if !ispg {
			return ret
		}
		if errors.Is(ret, pgError) {
			if pgError.Code == "23514" {
				ret = fmt.Errorf("Record doesnt meet regex")
			} else if pgError.Code == "23505" {
				ret = fmt.Errorf("Record with this name already exists")
			} else if pgError.Code == "23503" {
				return fmt.Errorf("Object is associated to other records.")
			}
		}
	}
	return ret
}

func DacEntityServerSave(logupn string, dest *Entity, orig *Entity, destAcc *Access, origAcc *Access) (err error) {
	db := Connection()
	var result *gorm.DB
	if merr := db.Transaction(func(tx *gorm.DB) error {
		if dest.ID == 0 {
			dest.Secret = utils.GenerateRandomString(64)
			result = tx.Create(dest)
			destAcc.EntityID = dest.ID
		} else {
			result = tx.Model(dest).Omit("secret").Updates(dest)
		}
		if result.Error != nil {
			return dacProcessGormResult(result)
		}
		recreateCert := dest.UPN != orig.UPN
		return dacAccessSave(tx, logupn, destAcc, origAcc, recreateCert)
	}); merr != nil {
		return dacProcessError(merr)
	}
	go CreateDNS(db)
	// change CRL
	go CreateCRL(db)
	return nil
}

func DacEntityCheckLoginInfo(u *Entity, cc *myjwt.CustomClaimsShieldoo, roles []string) error {
	if u.Origin == "invited" {
		if cc != nil {
			orig := cc.Provider
			if cc.Tenant != "" {
				orig += ":" + cc.Tenant
			}
			if err := DacEntitySetOrigin(u.ID, orig); err != nil {
				return err
			}
			if u.Name == "" {
				if err := DacEntitySetName(u.ID, cc.Name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func DacEntitySetOrigin(id int, origin string) error {
	db := Connection()
	merr := db.Model(&Entity{}).Where("id = ?", id).Update("origin", origin)
	return merr.Error
}

func DacEntitySetName(id int, name string) error {
	db := Connection()
	merr := db.Model(&Entity{}).Where("id = ?", id).Update("name", name)
	return merr.Error
}

func DacInviteUser(upn string, templateId int, dest *Entity, orig *Entity) (err error) {
	var t UserAccessTemplate
	t, err = DacUserAccessTemplateGet(templateId)
	if err != nil {
		return
	}
	err = DacEntitySave(upn, dest, orig)
	if err != nil {
		return
	}
	// create user access
	a := UserAccess{
		EntityID:             dest.ID,
		Name:                 t.Name,
		Description:          t.Description,
		UserAccessTemplateID: templateId,
		FwconfigID:           t.FwconfigID,
		ValidFrom:            t.ValidFrom,
		ValidTo:              t.ValidTo,
		UserAccessGroups:     []UserAccessGroup{},
	}
	for _, v := range t.UserAccessTemplateGroups {
		a.UserAccessGroups = append(a.UserAccessGroups,
			UserAccessGroup{GroupID: v.GroupID})
	}
	oa := a
	err = DacUserAccessSave(upn, &a, &oa)
	return
}

func DacUsersAll() (users []Entity, err error) {
	db := Connection()
	err = db.Where("entity_type = ?", ENTITY_USER).Find(&users).Error
	return
}

func DacImportUser(upn string, name string, isadmin bool, origin string, groups []Group) error {
	// check if user exists
	u, err := DacUserByUpn(upn)
	if err != nil {
		return err
	}
	var roles = `["USER"]`
	if isadmin {
		roles = `["USER","ADMINISTRATOR"]`
	}
	if u == nil {
		// create user
		log.Debug("DacImportUser creating user: " + upn)
		var orig Entity
		dest := Entity{
			UPN:        upn,
			Name:       name,
			Origin:     origin,
			Roles:      roles,
			EntityType: ENTITY_USER,
		}
		err := DacEntitySave("import", &dest, &orig)
		if err != nil {
			return err
		}
		t, err := DacUserAccessTemplateGet(ENTITY_DEFAULTTEMPLATE_ID)
		if err != nil {
			return err
		}
		// create user access
		a := UserAccess{
			EntityID:             dest.ID,
			Name:                 "import",
			Description:          "import",
			UserAccessTemplateID: t.ID,
			FwconfigID:           t.FwconfigID,
			ValidFrom:            t.ValidFrom,
			ValidTo:              t.ValidTo,
			UserAccessGroups:     []UserAccessGroup{},
		}
		for _, v := range groups {
			a.UserAccessGroups = append(a.UserAccessGroups,
				UserAccessGroup{GroupID: v.ID})
		}
		oa := a
		err = DacUserAccessSave(upn, &a, &oa)

		// send invitation email
		// go SendInvitationEmail(dest.UPN)
	} else {
		// update user
		if u.Name != name || u.Roles != roles || u.Origin != origin {
			orig := *u
			u.Name = name
			u.Roles = roles
			u.Origin = origin
			err := DacEntitySave("import", u, &orig)
			if err != nil {
				return err
			}
		}
		// if there is more UserAccesses, we have to clean up all of them except first one
		// if there is no UserAccesses, we have to create one
		// if there is only one UserAccess, we have to update it
		log.Debug("DacImportUser updating user: " + upn)
		if len(u.UserAccesses) > 1 {
			log.Debug("DacImportUser cleaning user accesses: " + upn)
			for i := 1; i < len(u.UserAccesses); i++ {
				err := DacUserAccessDelete(u.UserAccesses[i].ID, "import")
				if err != nil {
					return err
				}
			}
		}
		if len(u.UserAccesses) == 0 {
			log.Debug("DacImportUser creating user access: " + upn)
			t, err := DacUserAccessTemplateGet(ENTITY_DEFAULTTEMPLATE_ID)
			if err != nil {
				return err
			}
			// create user access
			a := UserAccess{
				EntityID:             u.ID,
				Name:                 "import",
				Description:          "import",
				UserAccessTemplateID: t.ID,
				FwconfigID:           t.FwconfigID,
				ValidFrom:            t.ValidFrom,
				ValidTo:              t.ValidTo,
				UserAccessGroups:     []UserAccessGroup{},
			}
			for _, v := range groups {
				a.UserAccessGroups = append(a.UserAccessGroups,
					UserAccessGroup{GroupID: v.ID})
			}
			oa := a
			err = DacUserAccessSave(upn, &a, &oa)
			if err != nil {
				return err
			}
		} else {
			// update user

			// update user access
			// we have to update only groups
			// if there is change in cert relevant data
			origgrps := []string{}
			for _, g := range u.UserAccesses[0].UserAccessGroups {
				origgrps = append(origgrps, strconv.Itoa(g.GroupID))
			}
			sort.Strings(origgrps)
			origg := strings.Join(origgrps, ",")
			destgrps := []string{}
			for _, g := range groups {
				destgrps = append(destgrps, strconv.Itoa(g.ID))
			}
			sort.Strings(destgrps)
			destg := strings.Join(destgrps, ",")
			if origg != destg {
				log.Debug("DacImportUser updating user access groups: " + upn)
				upd, err := DacUserAccessGet(u.UserAccesses[0].ID)
				if err != nil {
					return err
				}
				upd.UserAccessGroups = []UserAccessGroup{}
				for _, v := range groups {
					upd.UserAccessGroups = append(upd.UserAccessGroups,
						UserAccessGroup{GroupID: v.ID})
				}
				err = DacUserAccessSave("import", &upd, &u.UserAccesses[0])
				if err != nil {
					return err
				}
			} else {
				log.Debug("DacImportUser no changes in user access groups: " + upn)
			}
		}
	}
	return nil
}

func DacEntitySave(logupn string, dest *Entity, orig *Entity) (err error) {
	db := Connection()
	var result *gorm.DB
	isnew := dest.ID == 0
	entityRegenerated := false
	if merr := db.Transaction(func(tx *gorm.DB) error {
		if isnew {
			dest.Secret = utils.GenerateRandomString(64)
			result = tx.Create(dest)
		} else {
			result = tx.Model(dest).Omit("secret").Updates(dest)
		}
		if result.Error != nil {
			return dacProcessGormResult(result)
		}
		// we have to regenerate certs because UPN name is changed - it is part of certificate
		if !isnew && dest.UPN != orig.UPN {
			entityRegenerated = true
			e, err := DacEntityAccesses(dest.ID)
			if err != nil {
				return dacProcessError(err)
			}
			for _, i := range e.Accesses {
				if err := dacAccessSave(tx, logupn, &i, &i, true); err != nil {
					return dacProcessError(err)
				}
			}
		}
		return nil
	}); merr != nil {
		return dacProcessError(merr)
	}
	if entityRegenerated {
		go CreateDNS(db)
		// change CRL
		go CreateCRL(db)
	}
	return nil
}

func DacServerGetAll(name string) (dest []Entity, err error) {
	db := Connection()
	result := db
	if name != "" {
		result = result.Where("name ilike ? AND entity_type = ?", name, ENTITY_SERVER)
	} else {
		result = result.Where("entity_type = ?", ENTITY_SERVER)
	}
	result = result.
		Preload("Accesses").
		Preload("Accesses.AccessGroups").
		Preload("Accesses.AccessGroups.Group").
		Preload("Accesses.Fwconfig").
		Preload("Accesses.Fwconfig.Fwconfigouts").
		Preload("Accesses.Fwconfig.Fwconfigins").
		Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Order("name").Find(&dest)
	if result.Error != nil {
		return nil, dacProcessGormResult(result)
	}
	return dest, nil
}

func DacEntityList(entitytype int, filter string, origin string, preloadAccess bool, preloadUserAccess bool) (dest []Entity, err error) {
	db := Connection()
	tmp := db
	if preloadAccess {
		tmp = tmp.Preload("Accesses")
		tmp = tmp.Preload("Accesses.AccessStatistic")
		tmp = tmp.Preload("Accesses.AccessDevice")
		tmp = tmp.Preload("Accesses.AccessListeners")
		tmp = tmp.Preload("Accesses.AccessListeners.AccessListenerType")
	}
	if preloadUserAccess {
		tmp = tmp.Preload("UserAccesses.UserAccessTemplate")
		tmp = tmp.Preload("UserAccesses")
		tmp = tmp.Preload("UserAccesses.Accesses.AccessStatistic")
		tmp = tmp.Preload("UserAccesses.Accesses.AccessDevice")
	}
	result := tmp.
		Where("('' = @filter OR upn ilike @filter OR name ilike @filter) AND ('' = @origin OR origin = @origin) AND (entity_type = @etype)",
			sql.Named("filter", filter),
			sql.Named("origin", origin),
			sql.Named("etype", entitytype)).
		Order("upn").
		Limit(_cfg.Database.MaxRecords).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacEntityGet(id int) (dest Entity, err error) {
	db := Connection()
	result := db.First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacEntityDelete(id int, logupn string) (err error) {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		var d Entity
		if err = tx.Preload("UserAccesses").First(&d, "id = ?", id).Error; err != nil {
			return err
		}
		for _, i := range d.UserAccesses {
			if err = dacUserAccessDelete(tx, i.ID, logupn); err != nil {
				return err
			}
		}
		if err = tx.Preload("Accesses").First(&d, "id = ?", id).Error; err != nil {
			return err
		}
		for _, i := range d.Accesses {
			if err = dacAccessDelete(tx, i.ID, logupn); err != nil {
				return err
			}
		}
		if result := tx.Delete(&Entity{}, id); result.Error != nil {
			return dacProcessGormResult(result)
		} else if result.RowsAffected == 0 {
			return fmt.Errorf("No record found.")
		}
		return nil
	}); merr != nil {
		return dacProcessError(merr)
	}
	go CreateDNS(db)
	// change CRL
	go CreateCRL(db)

	return nil
}

func DacUserByUpn(upn string) (ret *Entity, err error) {
	db := Connection()
	var dest Entity
	result := db.First(&dest, "upn = ?", upn)
	err = result.Error
	if err == nil {
		dest, err = DacEntityAccesses(dest.ID)
		if err == nil {
			ret = &dest
		}
	} else {
		if err == gorm.ErrRecordNotFound {
			err = nil
		}
	}
	return
}

func DacEntityAccesses(id int) (dest Entity, err error) {
	db := Connection()
	var result *gorm.DB
	result = db.First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	if dest.EntityType == ENTITY_SERVER {
		result = db.
			Preload("Accesses").
			Preload("Accesses.AccessStatistic").
			Preload("Accesses.AccessDevice").
			Preload("Accesses.Fwconfig").
			Preload("Accesses.Fwconfig.Fwconfigouts").
			Preload("Accesses.Fwconfig.Fwconfigins").
			Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups").
			Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
			Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
			Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
			Preload("Accesses.AccessListeners").
			Preload("Accesses.AccessListeners.AccessListenerType").
			Preload("Accesses.AccessGroups").
			Preload("Accesses.AccessGroups.Group").
			First(&dest, "id = ?", id)
	} else {
		result = db.
			Preload("UserAccesses").
			Preload("UserAccesses.UserAccessTemplate").
			Preload("UserAccesses.Fwconfig").
			Preload("UserAccesses.Fwconfig.Fwconfigouts").
			Preload("UserAccesses.Fwconfig.Fwconfigins").
			Preload("UserAccesses.Fwconfig.Fwconfigouts.FwconfigGroups").
			Preload("UserAccesses.Fwconfig.Fwconfigins.FwconfigGroups").
			Preload("UserAccesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
			Preload("UserAccesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
			Preload("UserAccesses.UserAccessGroups").
			Preload("UserAccesses.UserAccessGroups.Group").
			Preload("UserAccesses.Accesses").
			Preload("UserAccesses.Accesses.AccessStatistic").
			Preload("UserAccesses.Accesses.AccessDevice").
			Preload("UserAccesses.Accesses.Fwconfig").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts.FwconfigGroups").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
			Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
			Preload("UserAccesses.Accesses.AccessListeners").
			Preload("UserAccesses.Accesses.AccessGroups").
			Preload("UserAccesses.Accesses.AccessGroups.Group").
			First(&dest, "id = ?", id)
	}
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacAllServers() (dest []Entity, err error) {
	db := Connection()
	result := db.
		Preload("Accesses").
		Preload("Accesses.AccessStatistic").
		Preload("Accesses.AccessDevice").
		Preload("Accesses.AccessListeners").
		Preload("Accesses.AccessListeners.AccessListenerType").
		Preload("Accesses.Fwconfig").
		Preload("Accesses.Fwconfig.Fwconfigins").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Where("entity_type = @etype", sql.Named("etype", ENTITY_SERVER)).
		Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacEntityMe(upn string) (dest Entity, err error) {
	db := Connection()
	result := db.
		Preload("UserAccesses").
		Preload("UserAccesses.Fwconfig").
		Preload("UserAccesses.Fwconfig.Fwconfigouts").
		Preload("UserAccesses.Fwconfig.Fwconfigins").
		Preload("UserAccesses.Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("UserAccesses.Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("UserAccesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("UserAccesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Preload("UserAccesses.UserAccessGroups").
		Preload("UserAccesses.UserAccessGroups.Group").
		Preload("UserAccesses.Accesses").
		Preload("UserAccesses.Accesses.AccessStatistic").
		Preload("UserAccesses.Accesses.AccessDevice").
		Preload("UserAccesses.Accesses.Fwconfig").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("UserAccesses.Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Preload("UserAccesses.Accesses.AccessListeners").
		Preload("UserAccesses.Accesses.AccessGroups").
		Preload("UserAccesses.Accesses.AccessGroups.Group").
		First(&dest, "upn = ? and entity_type = ?", strings.ToLower(upn), ENTITY_USER)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacFwconfigDelete(id int, logupn string) (err error) {
	if id == ENTITY_DEFAULTFIREWALL_ID {
		return errors.New("Default firewall config can't be deleted")
	}
	return dacGenericDelete(&Fwconfig{}, id, logupn)
}

func DacFwconfigSave(logupn string, dest *Fwconfig) (err error) {
	db := Connection()
	dest.Changed = time.Now().UTC()
	if merr := db.Transaction(func(tx *gorm.DB) error {

		if dest.ID == 0 {
			return tx.Create(dest).Error
		} else {
			if err := tx.Delete(Fwconfigout{}, "fwconfig_id = ?", dest.ID).Error; err != nil {
				return err
			}
			if err := tx.Delete(Fwconfigin{}, "fwconfig_id = ?", dest.ID).Error; err != nil {
				return err
			}
			return tx.Save(dest).Error
		}
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func DacFwconfigGetAll(name string) (dest []Fwconfig, err error) {
	db := Connection()
	result := db
	if name != "" {
		result = result.Where("name = ?", name)
	}
	result = result.
		Preload("Fwconfigouts").
		Preload("Fwconfigins").
		Preload("Fwconfigouts.FwconfigGroups").
		Preload("Fwconfigins.FwconfigGroups").
		Preload("Fwconfigouts.FwconfigGroups.Group").
		Preload("Fwconfigins.FwconfigGroups.Group").
		Order("name").Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacFwconfigList(filter string) (dest []Fwconfig, err error) {
	db := Connection()
	result := db.
		Where("('' = @filter OR name ilike @filter)",
			sql.Named("filter", filter)).
		Order("name").
		Limit(_cfg.Database.MaxRecords).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacFwconfigGet(id int) (dest Fwconfig, err error) {
	db := Connection()
	result := db.
		Preload("Fwconfigouts").
		Preload("Fwconfigins").
		Preload("Fwconfigouts.FwconfigGroups").
		Preload("Fwconfigins.FwconfigGroups").
		Preload("Fwconfigouts.FwconfigGroups.Group").
		Preload("Fwconfigins.FwconfigGroups.Group").
		First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacGroupDelete(id int, logupn string) (err error) {
	return dacGenericDelete(&Group{}, id, logupn)
}

func DacGroupSave(logupn string, dest *Group) (err error) {
	db := Connection()
	var result *gorm.DB
	if dest.ID == 0 {
		result = db.Create(dest)
	} else {
		result = db.Model(dest).Updates(dest)
	}
	return dacProcessGormResult(result)
}

func DacGroupGet(id int) (dest Group, err error) {
	db := Connection()
	result := db.First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacGroupGetAll(name string) (dest []Group, err error) {
	db := Connection()
	result := db
	if name != "" {
		result = result.Where("name = ?", name)
	}
	result = result.Find(&dest).Order("name")
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacGroupList(filter string) (dest []Group, err error) {
	db := Connection()
	result := db.
		Where("('' = @filter OR name ilike @filter)",
			sql.Named("filter", filter)).
		Order("name").
		Limit(_cfg.Database.MaxRecords).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacGroupsInFW() (dest []Group, err error) {
	db := Connection()
	subqueryIn := db.Table("fwconfigin_groups").Select("group_id")
	subqueryOut := db.Table("fwconfigout_groups").Select("group_id")
	result := db.Where("id IN (?) OR id IN (?)", subqueryIn, subqueryOut).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacGroupSaveFromImport(name string, fullName string, id string) error {
	db := Connection()
	var group Group
	result := db.First(&group, "object_id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			group = Group{
				Name:        name,
				Description: fullName,
				ObjectId:    id,
			}
			result = db.Create(&group)
			group.Name = fmt.Sprintf("%s-%d", name, group.ID)
			result = db.Save(&group)
			if result.Error != nil {
				return dacProcessError(result.Error)
			}
		} else {
			return dacProcessError(result.Error)
		}
	} else {
		group.Description = fullName
		result = db.Save(&group)
		if result.Error != nil {
			return dacProcessError(result.Error)
		}
	}
	return nil
}

func DacUserAccessTemplateDelete(id int, logupn string) (err error) {
	db := Connection()
	if result := db.Model(&UserAccessTemplate{}).Where("id = ?", id).Update("fwconfig_id", ENTITY_DEFAULTFIREWALL_ID); result.Error != nil {
		return dacProcessError(result.Error)
	}
	if result := db.Model(&UserAccessTemplate{}).Where("id = ?", id).Update("deleted", true); result.Error != nil {
		return dacProcessError(result.Error)
	}
	return nil
}

func DacUserAccessTemplateSave(logupn string, dest *UserAccessTemplate) (err error) {
	db := Connection()
	dest.Fwconfig = Fwconfig{}
	dest.Changed = time.Now().UTC()

	// cleanup groups
	for i := 0; i < len(dest.UserAccessTemplateGroups); i++ {
		dest.UserAccessTemplateGroups[i].Base.ID = 0
		dest.UserAccessTemplateGroups[i].UserAccessTemplateID = 0
		dest.UserAccessTemplateGroups[i].Group = Group{}
	}

	if merr := db.Transaction(func(tx *gorm.DB) error {
		if dest.ID == 0 {
			return tx.Create(dest).Error
		} else {
			if err := tx.Delete(UserAccessTemplateGroup{}, "user_access_template_id = ?", dest.ID).Error; err != nil {
				return err
			}
			if err := tx.Save(&dest).Error; err != nil {
				return err
			}
		}
		return nil
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func DacUserAccessTemplateGet(id int) (dest UserAccessTemplate, err error) {
	db := Connection()
	result := db.
		Preload("UserAccessTemplateGroups").
		Preload("UserAccessTemplateGroups.Group").
		Preload("Fwconfig").
		Preload("Fwconfig.Fwconfigouts").
		Preload("Fwconfig.Fwconfigins").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups.Group").
		First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacUserAccessTemplateList(filter string) (dest []UserAccessTemplate, err error) {
	db := Connection()
	result := db.
		Preload("UserAccessTemplateGroups").
		Preload("UserAccessTemplateGroups.Group").
		Where("deleted=false AND ('' = @filter OR name ilike @filter)",
			sql.Named("filter", filter)).
		Order("name").
		Limit(_cfg.Database.MaxRecords).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacAccessListenerTypeList(filter string) (dest []AccessListenerType, err error) {
	db := Connection()
	result := db.
		Where("('' = @filter OR name ilike @filter)",
			sql.Named("filter", filter)).
		Order("name").
		Limit(_cfg.Database.MaxRecords).Find(&dest)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func dacAccessDelete(tx *gorm.DB, id int, logupn string) (err error) {
	var access Access
	if err := tx.First(&access, id).Error; err != nil {
		return err
	}
	if err := tx.Where("ip = ?", access.IpAddress).Delete(&Ipam{}).Error; err != nil {
		return err
	}
	if err := tx.Delete(&access).Error; err != nil {
		return err
	}
	return nil
}

func DacAccessDelete(id int, logupn string) (err error) {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		return dacAccessDelete(tx, id, logupn)
	}); merr != nil {
		return dacProcessError(merr)
	}
	go CreateDNS(db)
	// change CRL
	go CreateCRL(db)
	return nil
}

func DacAccessSaveNote(logupn string, id int, note string) (err error) {
	db := Connection()
	result := db.Model(&Access{}).Where("id = ?", id).Update("description", note)
	return result.Error
}

func DacAccessSave(logupn string, dest *Access, orig *Access) (err error) {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		return dacAccessSave(tx, logupn, dest, orig, false)
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func DacAccessConvertUserAccessIdToAccessId(user_access_id int, client_id string) (aid int, err error) {
	db := Connection()
	if result := db.Raw("SELECT a.id FROM accesses a INNER JOIN access_devices d ON a.id = d.access_id WHERE a.user_access_id = ? AND d.device_id = ?",
		user_access_id, client_id).Scan(&aid); result.Error != nil {
		log.Error("DB error: ", result.Error)
		err = result.Error
	}
	return
}

func dacAccessCleanupOldAccessesForUser(logupn string, user_access_id int) {
	db := Connection()
	var aids []int
	if result := db.Raw("SELECT a.id FROM accesses a WHERE a.user_access_id = ? AND a.id NOT IN (SELECT ad.access_id FROM access_devices ad WHERE ad.contacted > (NOW() - INTERVAL '3 month'))",
		user_access_id).Scan(&aids); result.Error != nil {
		log.Error("DB error: ", result.Error)
	}
	anyAccessDeleted := false
	for _, v := range aids {
		dacAccessDelete(db, v, logupn)
		anyAccessDeleted = true
	}
	if anyAccessDeleted {
		go CreateDNS(db)
		// change CRL
		go CreateCRL(db)
	}
}

func DacAccessSaveDeviceStatisticsForDevice(logupn string, access_id int, device_name string, device_os string, client_version string) (err error) {
	dev := AccessDevice{
		AccessID:      access_id,
		DeviceID:      logupn,
		DeviceName:    device_name,
		DeviceOs:      device_os,
		Contacted:     time.Now().UTC(),
		ClientVersion: client_version,
	}
	db := Connection()
	return db.Omit("os_auto_update").Save(&dev).Error
}

func DacAccessCreateForUser(logupn string, user_access_id int, client_id string, device_name string, device_os string, client_version string, publickey string) (access Access, certificate string, err error) {
	log.Debug("DAC create access for user user_access_id: ", user_access_id)
	db := Connection()
	orig := Access{}
	// access for device dosn't exists
	if merr := db.Transaction(func(tx *gorm.DB) error {
		ua := UserAccess{}
		if err := tx.Preload("UserAccessGroups").First(&ua, user_access_id).Error; err != nil {
			return err
		}
		access = Access{
			Name:         ua.Name,
			Description:  ua.Description,
			FwconfigID:   ua.FwconfigID,
			EntityID:     ua.EntityID,
			ValidTo:      ua.ValidTo,
			UserAccessID: user_access_id,
			AccessGroups: []AccessGroup{},
		}
		for _, v := range ua.UserAccessGroups {
			access.AccessGroups = append(access.AccessGroups,
				AccessGroup{
					GroupID: v.GroupID,
				})
		}
		if er := dacAccessSaveBase(tx, logupn, &access, &orig, false, publickey); er != nil {
			return er
		}
		dev := AccessDevice{
			AccessID:      access.ID,
			DeviceName:    device_name,
			DeviceID:      client_id,
			DeviceOs:      device_os,
			Contacted:     time.Now().Add(720 * 24 * time.Hour).UTC(),
			ClientVersion: client_version,
		}
		return tx.Omit("os_auto_update").Create(&dev).Error
	}); merr != nil {
		err = dacProcessError(merr)
	}
	certificate = access.Certificate.SecretCrt
	return
}

func DacAccessCheckOrCreateForUser(logupn string, user_access_id int, client_id string, device_name string, device_os string, client_version string) (err error) {
	log.Debug("DAC create or check access for user user_access_id: ", user_access_id)
	var aid int
	if aid, err = DacAccessConvertUserAccessIdToAccessId(user_access_id, client_id); err != nil {
		return
	}
	db := Connection()
	if aid == 0 {
		// access for device dosn't exists
		if merr := db.Transaction(func(tx *gorm.DB) error {
			ua := UserAccess{}
			if err := tx.Preload("UserAccessGroups").First(&ua, user_access_id).Error; err != nil {
				return err
			}
			orig := Access{}
			dest := Access{
				Name:         ua.Name,
				Description:  ua.Description,
				FwconfigID:   ua.FwconfigID,
				EntityID:     ua.EntityID,
				ValidTo:      ua.ValidTo,
				UserAccessID: user_access_id,
				AccessGroups: []AccessGroup{},
			}
			for _, v := range ua.UserAccessGroups {
				dest.AccessGroups = append(dest.AccessGroups,
					AccessGroup{
						GroupID: v.GroupID,
					})
			}
			if er := dacAccessSave(tx, logupn, &dest, &orig, false); er != nil {
				return er
			}
			dev := AccessDevice{
				AccessID:      dest.ID,
				DeviceName:    device_name,
				DeviceID:      client_id,
				DeviceOs:      device_os,
				Contacted:     time.Now().UTC(),
				ClientVersion: client_version,
			}
			return tx.Omit("os_auto_update").Create(&dev).Error
		}); merr != nil {
			return dacProcessError(merr)
		}
	} else {
		// access exists -> update metadata
		dev := AccessDevice{}
		if err = db.First(&dev, "access_id = ?", aid).Error; err != nil {
			return
		}
		dev.Contacted = time.Now().UTC()
		dev.DeviceName = device_name
		dev.DeviceOs = device_os
		dev.ClientVersion = client_version
		return db.Omit("os_auto_update").Save(&dev).Error
	}

	// cleanup old accesses
	go dacAccessCleanupOldAccessesForUser(logupn, user_access_id)

	return
}

func dacAccessSave(tx *gorm.DB, logupn string, dest *Access, orig *Access, forceCertCreate bool) (err error) {
	return dacAccessSaveBase(tx, logupn, dest, orig, forceCertCreate, "")
}

func dacAccessCertGetPubKey(tx *gorm.DB, access_id int) (pubkey string, err error) {
	cert := Certificate{}
	if err = tx.First(&cert, "access_id = ?", access_id).Error; err != nil {
		return
	}
	pubkey = cert.SecretPublicKey
	return
}

func dacAccessSaveBase(tx *gorm.DB, logupn string, dest *Access, orig *Access, forceCertCreate bool, publicKey string) (err error) {

	log.Debug("DAC save access: ", dest)

	dest.Certificate = Certificate{}
	dest.Fwconfig = Fwconfig{}
	dest.Changed = time.Now().UTC()

	var requestedAddress net.IP
	log.Debug(fmt.Sprintf("DAC received IP: %v", dest.IpAddress))
	if len(dest.IpAddress) > 0 {
		requestedAddress = net.ParseIP(dest.IpAddress)
		if requestedAddress == nil {
			return fmt.Errorf("Invalid IP address requested.")
		}
	}
	// cleanup groups, firewal and listeners
	for i := 0; i < len(dest.AccessGroups); i++ {
		dest.AccessGroups[i].Base.ID = 0
		dest.AccessGroups[i].AccessID = 0
	}
	for i := 0; i < len(dest.AccessListeners); i++ {
		dest.AccessListeners[i].Base.ID = 0
		dest.AccessListeners[i].AccessID = 0
		dest.AccessListeners[i].AccessListenerType = AccessListenerType{}
	}

	if dest.ID == 0 {
		var err error
		_, err = AcquireIP(tx, dest, requestedAddress, true)
		if err != nil {
			return fmt.Errorf("Unable to acquire address: %s", err.Error())
		}

		if dest.Certificate, err = CreateCertAccess(tx, dest, publicKey); err != nil {
			return fmt.Errorf("Cannot create certificate: %s", err)
		}
		dest.ValidFrom = dest.Certificate.ValidFrom
		//create secret
		dest.Secret = utils.GenerateRandomString(64)
		if dest.UserAccessID == 0 {
			return tx.Omit("user_access_id").Create(dest).Error
		} else {
			return tx.Create(dest).Error
		}
	} else {
		var regenCert bool = false
		// if there is change in cert relevant data
		origgrps := []string{}
		for _, g := range orig.AccessGroups {
			origgrps = append(origgrps, strconv.Itoa(g.GroupID))
		}
		sort.Strings(origgrps)
		origg := strings.Join(origgrps, ",")
		destgrps := []string{}
		for _, g := range dest.AccessGroups {
			destgrps = append(destgrps, strconv.Itoa(g.GroupID))
		}
		sort.Strings(destgrps)
		destg := strings.Join(destgrps, ",")
		if forceCertCreate ||
			orig.Name != dest.Name ||
			orig.IpAddress != dest.IpAddress ||
			orig.ValidTo.UTC() != dest.ValidTo.UTC() ||
			origg != destg {
			log.Debug("changing certificate: important attribute changed")
			log.Debug("changing certificates orig-groups:", origg)
			log.Debug("changing certificates dest-groups:", destg)
			log.Debug("changing certificates orig-ValidTo:", orig.ValidTo.UTC())
			log.Debug("changing certificates dest-ValidTo:", dest.ValidTo.UTC())
			if publicKey, err = dacAccessCertGetPubKey(tx, dest.ID); err != nil {
				return fmt.Errorf("Cannot get public key: %s", err)
			}
			dest.Certificate = Certificate{}
			if dest.Certificate, err = CreateCertAccess(tx, dest, publicKey); err != nil {
				return fmt.Errorf("Cannot create certificate: %v", err)
			}
			regenCert = true
			dest.ValidFrom = dest.Certificate.ValidFrom
		} else {
			log.Debug("changing certificate: no change")
			dest.ValidFrom = orig.ValidFrom
		}
		if orig.IpAddress != dest.IpAddress {
			if err := tx.Where("ip = ?", orig.IpAddress).Delete(&Ipam{}).Error; err != nil {
				return err
			}
			var requestedAddress net.IP
			log.Debug(fmt.Sprintf("changing IP: %v", dest.IpAddress))
			if len(dest.IpAddress) > 0 {
				requestedAddress = net.ParseIP(dest.IpAddress)
				if requestedAddress == nil {
					return fmt.Errorf("invalid address requested: %s", dest.IpAddress)
				}
			}
			_, err = AcquireIP(tx, dest, requestedAddress, true)
			if err != nil {
				return fmt.Errorf("Unable to acquire address: %v", err.Error())
			}
		}

		if err := tx.Delete(AccessGroup{}, "access_id = ?", dest.ID).Error; err != nil {
			return err
		}
		if err := tx.Delete(AccessListener{}, "access_id = ?", dest.ID).Error; err != nil {
			return err
		}
		if regenCert {
			if err := tx.Model(&Certificate{}).Where("access_id = ?", dest.ID).Update("access_id", nil).Error; err != nil {
				return err
			}
		}
		if dest.UserAccessID == 0 {
			return tx.Omit("secret").Omit("user_access_id").Save(&dest).Error
		} else {
			return tx.Omit("secret").Save(&dest).Error
		}
	}
}

func DacFirstAccessIdByEntityID(eid int) (int, error) {
	var access []Access
	db := Connection()
	result := db.Where("entity_id = ?", eid).Find(&access)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Warn("server has no accesses: ", eid)
		} else {
			log.Error("Unable to connect to database: ", result.Error)
			return 0, result.Error
		}
	}
	if len(access) > 0 {
		return access[0].ID, nil
	} else {
		return 0, nil
	}
}

func DacAccessGet(id int) (dest Access, err error) {
	db := Connection()
	return dacAccessGet(db, id)
}

func dacAccessGet(tx *gorm.DB, id int) (dest Access, err error) {
	result := tx.
		Preload("Fwconfig").
		Preload("Fwconfig.Fwconfigouts").
		Preload("Fwconfig.Fwconfigins").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Preload("AccessListeners").
		Preload("AccessListeners.AccessListenerType").
		Preload("AccessGroups").
		Preload("AccessGroups.Group").
		First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacUserAccessDelete(id int, logupn string) (err error) {
	db := Connection()
	if merr := db.Transaction(func(tx *gorm.DB) error {
		return dacUserAccessDelete(tx, id, logupn)
	}); merr != nil {
		return dacProcessError(merr)
	}
	return nil
}

func dacUserAccessDelete(tx *gorm.DB, id int, logupn string) (err error) {
	var access UserAccess
	if err := tx.
		Preload("Accesses").
		First(&access, id).Error; err != nil {
		return err
	}
	for _, v := range access.Accesses {
		if err := dacAccessDelete(tx, v.ID, logupn); err != nil {
			return err
		}
	}
	if err := tx.Delete(&access).Error; err != nil {
		return err
	}
	return nil
}

func DacUserAccessSave(logupn string, dest *UserAccess, orig *UserAccess) (err error) {
	db := Connection()
	if dest.UserAccessTemplateID == 0 {
		dest.UserAccessTemplateID = ENTITY_DEFAULTTEMPLATE_ID
	}
	if merr := db.Transaction(func(tx *gorm.DB) error {
		return dacUserAccessSave(tx, logupn, dest, orig)
	}); merr != nil {
		return dacProcessError(merr)
	}
	go CreateCRL(db)
	return nil
}

func dacUserAccessSave(tx *gorm.DB, logupn string, dest *UserAccess, orig *UserAccess) (err error) {
	// check date
	if dest.ValidTo.UTC().Before(time.Now().UTC()) ||
		dest.ValidTo.UTC().After(SystemConfig().CA.ValidTo.UTC()) {
		return errors.New("Input format error, date ValidTo is out of range.")
	}

	dest.Fwconfig = Fwconfig{}
	dest.Changed = time.Now().UTC()

	// cleanup groups, firewal and listeners
	for i := 0; i < len(dest.UserAccessGroups); i++ {
		dest.UserAccessGroups[i].Base.ID = 0
		dest.UserAccessGroups[i].UserAccessID = 0
	}

	if dest.ID == 0 {
		dest.ValidFrom = time.Now().UTC()
		//create secret
		dest.Secret = utils.GenerateRandomString(64)
		return tx.Create(dest).Error
	} else {
		// if there is change in cert relevant data
		origgrps := []string{}
		for _, g := range orig.UserAccessGroups {
			origgrps = append(origgrps, strconv.Itoa(g.GroupID))
		}
		sort.Strings(origgrps)
		origg := strings.Join(origgrps, ",")
		destgrps := []string{}
		for _, g := range dest.UserAccessGroups {
			destgrps = append(destgrps, strconv.Itoa(g.GroupID))
		}
		sort.Strings(destgrps)
		destg := strings.Join(destgrps, ",")
		dest.ValidFrom = orig.ValidFrom
		if orig.ValidTo.UTC() != dest.ValidTo.UTC() ||
			origg != destg {
			log.Debug("changing certificates: important attribute changed!")
			log.Debug("changing certificates orig-groups:", origg)
			log.Debug("changing certificates dest-groups:", destg)
			log.Debug("changing certificates orig-ValidTo:", orig.ValidTo.UTC())
			log.Debug("changing certificates dest-ValidTo:", dest.ValidTo.UTC())
			for _, v := range orig.Accesses {
				if oa, aerr := DacAccessGet(v.ID); aerr != nil {
					return aerr
				} else {
					da := oa
					da.Fwconfig = Fwconfig{}
					da.FwconfigID = dest.FwconfigID
					da.Name = dest.Name
					da.ValidTo = dest.ValidTo
					da.AccessGroups = []AccessGroup{}
					for _, va := range dest.UserAccessGroups {
						da.AccessGroups = append(da.AccessGroups,
							AccessGroup{
								AccessID: da.ID,
								GroupID:  va.GroupID,
							})
					}
					if aerr = dacAccessSave(tx, logupn, &da, &oa, true); aerr != nil {
						return aerr
					}
				}
			}
		}

		if err := tx.Delete(UserAccessGroup{}, "user_access_id = ?", dest.ID).Error; err != nil {
			return err
		}
		dest.Accesses = []Access{}
		if err := tx.Omit("secret").Save(&dest).Error; err != nil {
			return err
		}
		return nil
	}
}

func DacUserAccessGet(id int) (dest UserAccess, err error) {
	db := Connection()
	result := db.
		Preload("Fwconfig").
		Preload("Fwconfig.Fwconfigouts").
		Preload("Fwconfig.Fwconfigins").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Preload("UserAccessGroups").
		Preload("UserAccessGroups.Group").
		Preload("Accesses").
		Preload("Accesses.AccessStatistic").
		Preload("Accesses.AccessDevice").
		Preload("Accesses.Fwconfig").
		Preload("Accesses.Fwconfig.Fwconfigouts").
		Preload("Accesses.Fwconfig.Fwconfigins").
		Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups").
		Preload("Accesses.Fwconfig.Fwconfigouts.FwconfigGroups.Group").
		Preload("Accesses.Fwconfig.Fwconfigins.FwconfigGroups.Group").
		Preload("Accesses.AccessListeners").
		Preload("Accesses.AccessGroups").
		Preload("Accesses.AccessGroups.Group").
		First(&dest, "id = ?", id)
	err = result.Error
	if err != nil {
		log.Error("DB error: ", result.Error)
	}
	return
}

func DacCheckUpnForUserAccess(upn string, UserAccessId int) (err error) {
	db := Connection()
	var ua UserAccess
	result := db.
		First(&ua, "id = ?", UserAccessId)
	err = result.Error
	if err != nil {
		log.Debug("DB error: ", err)
		return
	}
	if err == nil {
		var e Entity
		upnresult := db.First(&e, "id = ?", ua.EntityID)
		err = upnresult.Error
		if err != nil {
			log.Debug("DB error: ", err)
			return
		}
		if e.UPN != upn {
			err = errors.New("upn does not match")
		}
	}
	return
}

func DacCheckUpnForAccess(upn string, AccessId int) (err error) {
	db := Connection()
	var a Access
	result := db.
		First(&a, "id = ?", AccessId)
	err = result.Error
	if err != nil {
		log.Debug("DB error: ", err)
		return
	}
	if err == nil {
		var e Entity
		upnresult := db.First(&e, "id = ?", a.EntityID)
		err = upnresult.Error
		if err != nil {
			log.Debug("DB error: ", err)
			return
		}
		if e.UPN != upn {
			err = errors.New("upn does not match")
		}
	}
	return
}
