package graph

import (
	"fmt"

	"github.com/shieldoo/shieldoo-mesh-admin/aadimport"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
)

func aadLoadDryRun(tenantId string, clientId string, secret string, adminGroupOnjectId string) (bool, string) {
	log.Debug("AAD LOAD: run task")
	client, err := aadimport.CreateGraphClient(tenantId, clientId, secret)
	if err != nil {
		log.Debug("AAD LOAD: failed to create graph client: ", err)
		return false, fmt.Sprintf("failed to create graph client: %s", err)
	}

	// get current list of groups
	usedFwGroups, err := model.DacGroupsInFW()
	if err != nil {
		log.Debug("AAD LOAD: failed to get list of groups in Firewalls: ", err)
		return false, fmt.Sprintf("failed to get list of groups in Firewalls: %s", err)
	}
	var fwGroups []string
	for _, g := range usedFwGroups {
		if g.ObjectId != "" {
			fwGroups = append(fwGroups, g.ObjectId)
		}
	}

	// get AAD data
	aadGroups, aadUsers, err := aadimport.LoadGroupsAndUsers(client, adminGroupOnjectId, fwGroups)
	if err != nil {
		log.Debug("AAD LOAD: failed to load AAD data: ", err)
		return false, fmt.Sprintf("ERROR: failed to load AAD data: %s", err)
	}
	msg := fmt.Sprintf("loaded %d groups and %d users", len(aadGroups), len(aadUsers))
	log.Debug(msg)
	return true, msg
}
