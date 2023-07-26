package cliapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type Group struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	ObjectId string `json:"objectId"`
}

type FirewallRule struct {
	Protocol string  `json:"protocol"`
	Port     string  `json:"port"`
	Host     string  `json:"host"`
	Groups   []Group `json:"groups"`
}

type Firewall struct {
	Id       string         `json:"id"`
	Name     string         `json:"name"`
	RulesIn  []FirewallRule `json:"rulesIn"`
	RulesOut []FirewallRule `json:"rulesOut"`
}

type Listener struct {
	ListenPort  int    `json:"listenPort"`
	Protocol    string `json:"protocol"`
	ForwardPort int    `json:"forwardPort"`
	ForwardHost string `json:"forwardHost"`
	Description string `json:"description"`
}

type Server struct {
	Id             string                   `json:"id"`
	Name           string                   `json:"name"`
	Groups         []Group                  `json:"groups"`
	Firewall       Firewall                 `json:"firewall"`
	Listeners      []Listener               `json:"listeners"`
	Autoupdate     bool                     `json:"autoupdate"`
	IpAddress      string                   `json:"ipAddress"`
	Description    string                   `json:"description"`
	Configuration  string                   `json:"configuration"`
	OSUpdatePolicy ServerOSAutoupdatePolicy `json:"osUpdatePolicy"`
}

type ServerOSAutoupdatePolicy struct {
	Enabled                   bool `json:"enabled"`
	SecurityAutoupdateEnabled bool `json:"securityAutoupdateEnabled"`
	AllAutoupdateEnabled      bool `json:"allAutoupdateEnabled"`
	RestartAfterUpdate        bool `json:"restartAfterUpdate"`
	UpdateHour                int  `json:"updateHour"`
}

func translateGroupsToModelId(groups []Group, existingGroups *[]model.Group) ([]int, error) {
	ret := []int{}
	for _, g := range groups {
		searchId := extractId(g.Id, "groups")
		// check if group exists
		var id int = 0
		for _, eg := range *existingGroups {
			if searchId == eg.ID {
				id = eg.ID
				break
			}
			if g.ObjectId != "" && g.ObjectId == eg.ObjectId {
				id = eg.ID
				break
			}
			if g.Name != "" && g.Name == eg.Name {
				id = eg.ID
				break
			}
		}
		if id == 0 {
			return ret, errors.New("Group does not exist; name:" + g.Name + ", objectId:" + g.ObjectId + ", id:" + g.Id)
		}
		ret = append(ret, id)
	}
	return ret, nil
}

func checkFwRules(r FirewallRule) error {
	// check Port
	if ok, err := regexp.Match(`^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$|^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$|^any$`, []byte(r.Port)); !ok || err != nil {
		return errors.New("The value must either be a single number from the standard port range (1-65535), a port range (e.g. 80-90), or 'any'.")
	}
	// check Protocol
	// icmp, tcp, udp, any
	if ok, err := regexp.Match(`^(icmp|tcp|udp|any)$`, []byte(r.Protocol)); !ok || err != nil {
		return errors.New("The value must be one of 'icmp', 'tcp', 'udp', or 'any'.")
	}
	// check Host
	// any, group
	if ok, err := regexp.Match(`^(any|group)$`, []byte(r.Host)); !ok || err != nil {
		return errors.New("The value must be one of 'any' or 'group'.")
	}
	return nil
}

func extractId(id string, resource string) int {
	// parse id fro last position in string with : as separator
	ret := strings.ReplaceAll(id, getShieldooHostname()+":"+resource+":", "")
	var reti int = 0
	reti, _ = strconv.Atoi(ret)
	return reti
}

func generateConfigFromAccess(a *model.Access) string {
	if a == nil {
		return ""
	}
	cfg, derr := model.DownloadGenereateMyconfig(a)
	if derr != nil {
		cfg = ""
	}
	cfg = base64.StdEncoding.EncodeToString([]byte(cfg))
	return cfg
}

func translateFWToModel(fw *Firewall) (model.Fwconfig, error) {
	ret := model.Fwconfig{
		Name:    fw.Name,
		Changed: time.Now().UTC(),
	}

	// get groups for translation
	existingGroups, err := model.DacGroupGetAll("")
	if err != nil {
		return ret, errors.New("Failed to get groups for translation")
	}

	// translate rules
	for _, r := range fw.RulesIn {
		if err := checkFwRules(r); err != nil {
			return ret, err
		}
		fwgroups := []model.FwconfiginGroup{}
		if r.Host == "group" {
			// translate groups
			groups, err := translateGroupsToModelId(r.Groups, &existingGroups)
			if err != nil {
				return ret, err
			}
			for _, g := range groups {
				fwgroups = append(fwgroups, model.FwconfiginGroup{
					GroupID: g,
				})
			}
		}
		ret.Fwconfigins = append(ret.Fwconfigins, model.Fwconfigin{
			Proto:          r.Protocol,
			Port:           r.Port,
			Host:           r.Host,
			FwconfigGroups: fwgroups,
		})
	}
	for _, r := range fw.RulesOut {
		if err := checkFwRules(r); err != nil {
			return ret, err
		}
		fwgroups := []model.FwconfigoutGroup{}
		if r.Host == "group" {
			// translate groups
			groups, err := translateGroupsToModelId(r.Groups, &existingGroups)
			if err != nil {
				return ret, err
			}
			for _, g := range groups {
				fwgroups = append(fwgroups, model.FwconfigoutGroup{
					GroupID: g,
				})
			}
		}
		ret.Fwconfigouts = append(ret.Fwconfigouts, model.Fwconfigout{
			Proto:          r.Protocol,
			Port:           r.Port,
			Host:           r.Host,
			FwconfigGroups: fwgroups,
		})
	}
	return ret, nil
}

func fwconfigRulesInToString(fw *[]model.Fwconfigin) string {
	ret := ""
	var arr []string
	for _, r := range *fw {
		x := r.Proto + "|" + r.Port + "|" + r.Host + "|"
		var ids []int
		for _, g := range r.FwconfigGroups {
			ids = append(ids, g.GroupID)
		}
		sort.Ints(ids)
		for _, id := range ids {
			x += strconv.Itoa(id) + ","
		}
		arr = append(arr, x)
	}
	sort.Strings(arr)
	for _, x := range arr {
		ret += x + ";"
	}
	return ret
}

func fwconfigRulesOutToString(fw *[]model.Fwconfigout) string {
	ret := ""
	var arr []string
	for _, r := range *fw {
		x := r.Proto + "|" + r.Port + "|" + r.Host + "|"
		var ids []int
		for _, g := range r.FwconfigGroups {
			ids = append(ids, g.GroupID)
		}
		sort.Ints(ids)
		for _, id := range ids {
			x += strconv.Itoa(id) + ","
		}
		arr = append(arr, x)
	}
	sort.Strings(arr)
	for _, x := range arr {
		ret += x + ";"
	}
	return ret
}

func isEqualFwconfigModel(a *model.Fwconfig, b *model.Fwconfig) bool {
	astr := a.Name + "|" + fwconfigRulesInToString(&a.Fwconfigins) + "|" + fwconfigRulesOutToString(&a.Fwconfigouts)
	bstr := b.Name + "|" + fwconfigRulesInToString(&b.Fwconfigins) + "|" + fwconfigRulesOutToString(&b.Fwconfigouts)
	return astr == bstr
}

func checkGroupChanged(a *[]model.AccessGroup, b *[]model.AccessGroup) bool {
	if len(*a) != len(*b) {
		return true
	}
	var arr1 []int
	for _, g := range *a {
		arr1 = append(arr1, g.GroupID)
	}
	var arr2 []int
	for _, g := range *b {
		arr2 = append(arr2, g.GroupID)
	}
	sort.Ints(arr1)
	sort.Ints(arr2)
	for i, g := range arr1 {
		if g != arr2[i] {
			return true
		}
	}
	return false
}

func checkListenerChanged(a *[]model.AccessListener, b *[]model.AccessListener) bool {
	if len(*a) != len(*b) {
		return true
	}
	var arr1 []string
	for _, g := range *a {
		arr1 = append(arr1, fmt.Sprintf("%d|%s|%s|%d|%s", g.ListenPort, g.Protocol, g.ForwardHost, g.ForwardPort, g.Description))
	}
	var arr2 []string
	for _, g := range *b {
		arr2 = append(arr2, fmt.Sprintf("%d|%s|%s|%d|%s", g.ListenPort, g.Protocol, g.ForwardHost, g.ForwardPort, g.Description))
	}
	sort.Strings(arr1)
	sort.Strings(arr2)
	for i, g := range arr1 {
		if g != arr2[i] {
			return true
		}
	}
	return false
}

func translateServerToOriginalModel(orig *model.Entity, s *Server) (bool, model.Entity, model.Access, error) {
	log.Debug("translateServerToOriginalModel")
	m, a, err := translateServerToModel(s)
	if err != nil {
		return false, m, a, err
	}
	if orig == nil {
		return false, m, a, errors.New("Original model is nil")
	}
	var origacc model.Access
	if len(orig.Accesses) > 0 {
		origacc = orig.Accesses[0]
	}
	var groupsChanged, listenerChanged, autoupdateChanged bool
	// check if groups changed
	groupsChanged = checkGroupChanged(&origacc.AccessGroups, &a.AccessGroups)
	log.Debug("translateServerToOriginalModel - groupsChanged ", groupsChanged)
	// check if listener changed
	listenerChanged = checkListenerChanged(&origacc.AccessListeners, &a.AccessListeners)
	log.Debug("translateServerToOriginalModel - listenerChanged ", listenerChanged)
	// check if autoupdate changed
	if origacc.Autoupdate != nil && a.Autoupdate != nil {
		autoupdateChanged = *origacc.Autoupdate != *a.Autoupdate
	} else {
		autoupdateChanged = true
	}
	log.Debug("translateServerToOriginalModel - autoupdateChanged ", autoupdateChanged)
	// check if changed
	if !groupsChanged && !listenerChanged &&
		orig.Name == m.Name &&
		orig.UPN == m.UPN &&
		orig.Description == m.Description &&
		origacc.Name == a.Name &&
		origacc.FQDN == a.FQDN &&
		(origacc.IpAddress == a.IpAddress || a.IpAddress == "") &&
		origacc.FwconfigID == a.FwconfigID &&
		!autoupdateChanged &&
		origacc.ValidTo == a.ValidTo &&
		origacc.OSAutoupdateConfig == a.OSAutoupdateConfig &&
		orig.EntityType == m.EntityType {
		log.Debug("translateServerToOriginalModel - no change ")
		return false, m, a, nil
	}
	// there is change, get data from original object
	var nebulaPunchBack, nebulaRestrictiveNetwork bool
	if origacc.NebulaPunchBack != nil {
		nebulaPunchBack = *origacc.NebulaPunchBack
	}
	if origacc.NebulaRestrictiveNetwork != nil {
		nebulaRestrictiveNetwork = *origacc.NebulaRestrictiveNetwork
	}
	m.ID = orig.ID
	m.Origin = orig.Origin
	m.Roles = orig.Roles
	m.Secret = orig.Secret
	a.Description = origacc.Description
	a.ID = origacc.ID
	a.EntityID = origacc.EntityID
	a.Secret = origacc.Secret
	a.NebulaPunchBack = &nebulaPunchBack
	a.NebulaRestrictiveNetwork = &nebulaRestrictiveNetwork
	if a.IpAddress == "" {
		a.IpAddress = origacc.IpAddress
	}
	return true, m, a, nil
}

func translateServerToModel(s *Server) (model.Entity, model.Access, error) {
	ret := model.Entity{
		Name:        s.Name,
		UPN:         s.Name,
		EntityType:  model.ENTITY_SERVER,
		Description: s.Description,
	}
	// access
	acc := model.Access{
		Name:       s.Name,
		FQDN:       s.Name,
		IpAddress:  s.IpAddress,
		FwconfigID: 0,
		ValidFrom:  time.Now().UTC(),
		ValidTo:    model.SystemConfig().CA.ValidTo,
		Autoupdate: &s.Autoupdate,
	}

	// check name regex
	re := regexp.MustCompile(`^[0-9a-zA-Z-.]{1,256}$`)
	if !re.MatchString(s.Name) {
		return ret, acc, fmt.Errorf("Name is not valid - contains invalid characters")
	}
	// get groups for translation
	existingGroups, err := model.DacGroupGetAll("")
	if err != nil {
		return ret, acc, errors.New("Failed to get groups for translation")
	}
	// check firewall
	fwId := extractId(s.Firewall.Id, "firewalls")
	_, err = model.DacFwconfigGet(fwId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ret, acc, errors.New("Firewall not found")
		}
		return ret, acc, err
	}
	acc.FwconfigID = fwId
	// check ip address
	if s.IpAddress != "" && !regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`).MatchString(s.IpAddress) {
		return ret, acc, errors.New("IpAddress is not valid")
	}

	// translate groups
	groups, err := translateGroupsToModelId(s.Groups, &existingGroups)
	if err != nil {
		return ret, acc, err
	}
	for _, g := range groups {
		acc.AccessGroups = append(acc.AccessGroups, model.AccessGroup{
			GroupID: g,
		})
	}
	for _, l := range s.Listeners {
		// check listener attributes
		if l.ListenPort < 1 || l.ListenPort > 65535 {
			return ret, acc, errors.New("ListenPort is not valid")
		}
		if l.ForwardPort < 1 || l.ForwardPort > 65535 {
			return ret, acc, errors.New("ForwardPort is not valid")
		}
		if l.ForwardHost == "" {
			return ret, acc, errors.New("ForwardHost is not valid")
		}
		if l.Protocol != "tcp" && l.Protocol != "udp" {
			return ret, acc, errors.New("Protocol is not valid")
		}
		acc.AccessListeners = append(acc.AccessListeners, model.AccessListener{
			ListenPort:  l.ListenPort,
			Protocol:    l.Protocol,
			ForwardPort: l.ForwardPort,
			ForwardHost: l.ForwardHost,
			Description: l.Description,
		})
	}
	// OS update policy
	acc.OSAutoupdateConfig = ""
	if barr, err := json.Marshal(s.OSUpdatePolicy); err == nil {
		acc.OSAutoupdateConfig = string(barr)
	}
	return ret, acc, nil
}
