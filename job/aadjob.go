package job

import (
	"fmt"
	"sort"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/aadimport"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
	log "github.com/sirupsen/logrus"
)

const keyStoreKey = "AADTASK"

func aadJob() {
	for {
		// once per 20 minutes (60 * 20 seconds)
		for i := 0; i < 60; i++ {
			time.Sleep(time.Duration(20) * time.Second)
			if utils.GetBreakAADWaitLoop() {
				utils.SetAADWaitLoop()
				break
			}
		}
		log.Debug("AAD JOB - run job: ", model.SystemConfig().AADSyncConfig.Enabled)
		if model.SystemConfig().AADSyncConfig.Enabled {
			ret := aadTask()
			// add current timestamp to message
			ret = fmt.Sprintf("%s - %s", time.Now().Format("2006-01-02 15:04:05"), ret)
			model.DacSaveKey(keyStoreKey, ret)
		}
	}
}

func aadTask() string {
	log.Debug("AAD TASK: run task")
	syscfg := model.SystemConfig()
	// create Graph client
	client, err := aadimport.CreateGraphClient(
		syscfg.AADSyncConfig.AADTenantID,
		syscfg.AADSyncConfig.AADClientID,
		syscfg.AADSyncConfig.AADClientSecret)
	if err != nil {
		log.Error("AAD TASK: failed to create graph client: ", err)
		return err.Error()
	}
	log.Debug("AAD TASK: graph client created")

	// get current list of groups
	usedFwGroups, err := model.DacGroupsInFW()
	if err != nil {
		log.Error("AAD TASK: failed to get list of groups in FW: ", err)
		return err.Error()
	}
	var fwGroups []string
	for _, g := range usedFwGroups {
		if g.ObjectId != "" {
			fwGroups = append(fwGroups, g.ObjectId)
		}
	}
	log.Debug("AAD TASK: loaded FW groups: ", fwGroups)

	// get AAd data
	aadGroups, aadUsers, err := aadimport.LoadGroupsAndUsers(client, syscfg.AADSyncConfig.AdminGroupID, fwGroups)
	if err != nil {
		log.Error("AAD TASK: failed to load groups and users: ", err)
		return err.Error()
	}
	ret := fmt.Sprintf("AAD TASK: loaded %d groups and %d users", len(aadGroups), len(aadUsers))
	log.Debug(ret)

	// delete unused groups
	log.Debug("AAD TASK: deleting unused groups")
	modelGroups, err := model.DacGroupGetAll("")
	if err != nil {
		log.Error("AAD TASK: failed to get list of groups: ", err)
		return err.Error()
	}
	err = aadTaskDeleteGroups(aadGroups, modelGroups)
	if err != nil {
		log.Error("AAD TASK: failed to delete groups: ", err)
		return err.Error()
	}

	// process groups
	log.Debug("AAD TASK: processing groups")
	err = aadTaskProcessGroups(aadGroups)
	if err != nil {
		log.Error("AAD TASK: failed to process groups: ", err)
		return err.Error()
	}

	// reduce groups
	redGroups := reduceGroups(fwGroups, aadGroups)

	// delete unused users
	log.Debug("AAD TASK: deleting unused users")
	modelUsers, err := model.DacUsersAll()
	if err != nil {
		log.Error("AAD TASK: failed to get list of users: ", err)
		return err.Error()
	}
	err = aadTaskDeleteUsers(aadUsers, modelUsers)
	if err != nil {
		log.Error("AAD TASK: failed to delete users: ", err)
		return err.Error()
	}

	// create all new users (or change roles)
	log.Debug("AAD TASK: processing users")
	err = aadTaskProcessUsers(aadUsers, redGroups, usedFwGroups)
	if err != nil {
		log.Error("AAD TASK: failed to process users: ", err)
		return err.Error()
	}

	log.Debug("AAD TASK: finished")
	return ret
}

func aadTaskDeleteGroups(groups []aadimport.ADGroups, modelGroups []model.Group) error {
	m := make(map[string]aadimport.ADGroups)
	for _, g := range groups {
		m[g.Id] = g
	}
	for _, g := range modelGroups {
		if g.ObjectId == "" {
			continue
		}
		if _, ok := m[g.ObjectId]; !ok {
			log.Debug("AAD TASK: deleting group: ", g.ObjectId)
			err := model.DacGroupDelete(g.ID, "import")
			if err != nil {
				log.Debug("AAD TASK: failed to delete group: ", err)
			}
		}
	}
	return nil
}

func aadTaskDeleteUsers(users []aadimport.ADUsers, modelUsers []model.Entity) error {
	m := make(map[string]aadimport.ADUsers)
	for _, u := range users {
		m[u.Upn] = u
	}
	for _, u := range modelUsers {
		if _, ok := m[u.UPN]; !ok {
			log.Debug("AAD TASK: deleting user: ", u.UPN)
			err := model.DacEntityDelete(u.ID, "import")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func aadTaskProcessUsers(users []aadimport.ADUsers, groups []aadimport.ADGroups, fwGroups []model.Group) error {
	mapGroups := make(map[string]model.Group)
	for _, g := range fwGroups {
		mapGroups[g.ObjectId] = g
	}
	for _, u := range users {
		var myGroups []model.Group
		for _, g := range findUsersGroups(u, groups) {
			if mg, ok := mapGroups[g]; ok {
				myGroups = append(myGroups, mg)
			}
		}
		// create or update user
		log.Debug("AAD TASK: processing user: ", u.Upn, " - ", u.Name, ", IsAdmin: ", u.IsAdmin, ", ", len(myGroups), " groups")
		origin := fmt.Sprintf("microsoft:%s", model.SystemConfig().AADSyncConfig.AADTenantID)
		err := model.DacImportUser(u.Upn, u.Name, u.IsAdmin, origin, myGroups)
		if err != nil {
			return err
		}
	}
	return nil
}

func reduceGroups(fwGroups []string, groups []aadimport.ADGroups) []aadimport.ADGroups {
	var ret []aadimport.ADGroups
	sort.Strings(fwGroups)
	for _, g := range groups {
		idx := sort.SearchStrings(fwGroups, g.Id)
		if idx < len(fwGroups) && fwGroups[idx] == g.Id {
			ret = append(ret, g)
		}
	}
	return ret
}

func findUsersGroups(user aadimport.ADUsers, groups []aadimport.ADGroups) []string {
	var ret []string
	for _, g := range groups {
		for _, u := range g.Users {
			if u.Id == user.Id {
				ret = append(ret, g.Id)
				break
			}
		}
	}
	return ret
}

func aadTaskProcessGroups(groups []aadimport.ADGroups) error {
	for _, g := range groups {
		err := model.DacGroupSaveFromImport(
			g.NormalizedName,
			fmt.Sprintf("%s (%s)", g.Name, g.Id),
			g.Id,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
