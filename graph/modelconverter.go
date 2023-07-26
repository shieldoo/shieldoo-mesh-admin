package graph

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"

	gqlmodel "github.com/shieldoo/shieldoo-mesh-admin/graph/model"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	log "github.com/sirupsen/logrus"
)

func modelconvUserRoles2Gql(r string) []*string {
	var roles []*string
	var dacroles []string
	if json.Unmarshal([]byte(r), &dacroles) == nil {
		for _, i := range dacroles {
			if i != model.ROLE_USER {
				// make a copy of string because we need to store pointer to array
				j := i
				roles = append(roles, &j)
			}
		}
	}
	ru := model.ROLE_USER
	roles = append(roles, &ru)
	return roles
}

func modelconvGql2UserRoles(r []*string) string {
	var roles []string
	for _, i := range r {
		// check if role is in list of selected roles!
		if *i == model.ROLE_ADMINISTRATOR {
			j := *i
			roles = append(roles, j)
		}
	}
	roles = append(roles, model.ROLE_USER)
	data, _ := json.Marshal(roles)
	return string(data)
}

func modelconvGql2UserEntity(e gqlmodel.UserData, m *model.Entity) {
	m.UPN = e.Upn
	m.Name = e.Name
	if e.ID != nil {
		m.ID = *e.ID
	}
	if e.Description != nil {
		m.Description = *e.Description
	}
	if e.Origin != nil {
		m.Origin = *e.Origin
	}
	m.Roles = modelconvGql2UserRoles(e.Roles)
	m.EntityType = model.ENTITY_USER
}

func modelconvGqlInvite2UserEntity(e gqlmodel.InviteUserData, m *model.Entity) {
	m.UPN = e.Upn
	m.Name = e.Name
	if e.Description != nil {
		m.Description = *e.Description
	}
	m.Origin = "invited"
	m.Roles = modelconvGql2UserRoles(e.Roles)
	m.EntityType = model.ENTITY_USER
}

func modelconvGql2ServerEntity(e *gqlmodel.ServerData, m *model.Entity) {
	m.Name = e.Name
	m.UPN = e.Name
	if e.ID != nil {
		m.ID = *e.ID
	}
	if e.Description != nil {
		m.Description = *e.Description
	}
	m.EntityType = model.ENTITY_SERVER
}

func modelconvGqlUserAccess2UserAccess(e gqlmodel.UserAccessData, m *model.UserAccess) {
	if e.ID != nil {
		m.ID = *e.ID
	}
	if e.Description != nil {
		m.Description = *e.Description
	}
	m.EntityID = e.EntityID
	m.Name = e.Name
	m.FwconfigID = e.FwConfigID
	m.ValidTo = convertJsonDate2Date(e.ValidTo)
	if e.UserAccessTemplateID != nil {
		m.UserAccessTemplateID = *e.UserAccessTemplateID
	}
	m.UserAccessGroups = []model.UserAccessGroup{}
	for _, i := range e.GroupsIds {
		m.UserAccessGroups = append(m.UserAccessGroups, model.UserAccessGroup{UserAccessID: m.ID, GroupID: i})
	}
}

func modelconvGqlServerAccess2Access(entityId int, accessId int, e gqlmodel.ServerAccessData, fqdn string, autoupdate bool, m *model.Access) {
	if e.Description != nil {
		m.Description = *e.Description
	}
	m.ID = accessId
	m.FQDN = fqdn
	m.EntityID = entityId
	m.FwconfigID = e.FwConfigID
	m.ValidTo = convertJsonDate2Date(e.ValidTo)
	m.NebulaPunchBack = &e.PunchBack
	m.NebulaRestrictiveNetwork = &e.RestrictiveNetwork
	m.Autoupdate = &autoupdate
	m.AccessGroups = []model.AccessGroup{}
	m.AccessListeners = []model.AccessListener{}
	if e.IPAddress != nil {
		m.IpAddress = *e.IPAddress
	}
	for _, i := range e.GroupsIds {
		m.AccessGroups = append(m.AccessGroups, model.AccessGroup{AccessID: m.ID, GroupID: i})
	}
	for _, i := range e.Listeners {
		j := model.AccessListener{
			AccessID:             accessId,
			ListenPort:           i.ListenPort,
			Protocol:             i.Protocol,
			ForwardPort:          i.ForwardPort,
			ForwardHost:          i.ForwardHost,
			AccessListenerTypeID: i.AccessListenerTypeID,
		}
		j.Description = i.Description
		m.AccessListeners = append(m.AccessListeners, j)
	}
}

func modelconvCodeListItems2Gql(c []model.CodeListItem) (g []*gqlmodel.CodeListItem) {
	for _, i := range c {
		item := gqlmodel.CodeListItem{
			ID:   i.ID,
			Name: i.Name,
		}
		g = append(g, &item)
	}
	return
}

func modelconvGql2Group(e gqlmodel.GroupData, m *model.Group) {
	m.Name = e.Name
	if e.ID != nil {
		m.ID = *e.ID
	}
	if e.Description != nil {
		m.Description = *e.Description
	}
}

func modelconvGql2UserAccessTemplate(e gqlmodel.UserAccessTemplateData, m *model.UserAccessTemplate) {
	m.Name = e.Name
	m.Deleted = &e.Deleted
	if e.ID != nil {
		m.ID = *e.ID
	}
	if e.Description != nil {
		m.Description = *e.Description
	}
	m.FwconfigID = e.FwConfigID
	m.ValidTo = convertJsonDate2Date(e.ValidTo)
	for _, i := range e.GroupsIds {
		m.UserAccessTemplateGroups = append(m.UserAccessTemplateGroups, model.UserAccessTemplateGroup{UserAccessTemplateID: m.ID, GroupID: i})
	}
}

func modelconvGql2Fwconfig(e gqlmodel.FwConfigData, m *model.Fwconfig) {
	if e.Name != nil {
		m.Name = *e.Name
	}
	if e.ID != nil {
		m.ID = *e.ID
	}
	m.Fwconfigins = []model.Fwconfigin{}
	m.Fwconfigouts = []model.Fwconfigout{}

	if e.FwConfigIns != nil {
		for _, i := range e.FwConfigIns {
			f := model.Fwconfigin{Port: i.Port, Proto: i.Proto, Host: i.Host, FwconfigGroups: []model.FwconfiginGroup{}}
			if i.Groups != nil {
				for _, j := range i.Groups {
					f.FwconfigGroups = append(f.FwconfigGroups, model.FwconfiginGroup{GroupID: *j.ID})
				}
			}
			m.Fwconfigins = append(m.Fwconfigins, f)
		}
	}
	if e.FwConfigOuts != nil {
		for _, i := range e.FwConfigOuts {
			f := model.Fwconfigout{Port: i.Port, Proto: i.Proto, Host: i.Host, FwconfigGroups: []model.FwconfigoutGroup{}}
			if i.Groups != nil {
				for _, j := range i.Groups {
					f.FwconfigGroups = append(f.FwconfigGroups, model.FwconfigoutGroup{GroupID: *j.ID})
				}
			}
			m.Fwconfigouts = append(m.Fwconfigouts, f)
		}
	}
}

func modelconvEntityUser2Gql(d model.Entity) gqlmodel.User {
	var e gqlmodel.User
	var roles []*string
	var dacroles []string
	if json.Unmarshal([]byte(d.Roles), &dacroles) == nil {
		for _, i := range dacroles {
			j := i
			roles = append(roles, &j)
		}
	}
	// process accesses
	var accs []*gqlmodel.UserAccess
	for _, a := range d.UserAccesses {
		gqla := modelconvUserAccess2Gql(a)
		accs = append(accs, &gqla)
	}
	e = gqlmodel.User{
		ID:           d.ID,
		Upn:          d.UPN,
		Name:         d.Name,
		Description:  &d.Description,
		UserAccesses: accs,
		Origin:       &d.Origin,
		Roles:        roles,
	}
	return e
}

func modelconvEntityServer2Gql(d model.Entity) gqlmodel.Server {
	var e gqlmodel.Server
	// process accesses
	var a gqlmodel.Access
	var updPolicy gqlmodel.ServerOSAutoUpdatePolicy
	autoupdate := false
	if len(d.Accesses) > 0 {
		a = modelconvAccess2Gql(d.Accesses[0])
		if d.Accesses[0].Autoupdate != nil {
			autoupdate = *d.Accesses[0].Autoupdate
		}
		updPolicy = modelconvOSAutoupdatePolicy2Gql(d.Accesses[0])
	}
	e = gqlmodel.Server{
		ID:                       d.ID,
		Name:                     d.Name,
		Description:              &d.Description,
		AllowAutoUpdate:          autoupdate,
		Access:                   &a,
		ServerOSAutoUpdatePolicy: &updPolicy,
	}
	return e
}

func modelconvOSAutoupdatePolicy2Gql(a model.Access) gqlmodel.ServerOSAutoUpdatePolicy {
	var ret gqlmodel.ServerOSAutoUpdatePolicy

	// json unmarchal from access
	if a.OSAutoupdateConfig != "" {
		var updPolicy model.OSAutoupdateConfigType
		if json.Unmarshal([]byte(a.OSAutoupdateConfig), &updPolicy) == nil {
			ret.OsAutoUpdateEnabled = updPolicy.Enabled
			ret.OsAutoUpdateHour = updPolicy.UpdateHour
			ret.SecurityAutoUpdateEnabled = updPolicy.SecurityAutoupdateEnabled
			ret.AllAutoUpdateEnabled = updPolicy.AllAutoupdateEnabled
			ret.RestartAfterUpdate = updPolicy.RestartAfterUpdate
		}
	}

	return ret
}

func modelconvAccess2Gql(a model.Access) gqlmodel.Access {
	var grps []*gqlmodel.Group
	for _, i := range a.AccessGroups {
		g := modelconvGroup2Gql(i.Group)
		grps = append(grps, &g)
	}

	fwconf := modelconvFwConfig2Gql(a.Fwconfig)

	cfg, derr := model.DownloadGenereateMyconfig(&a)
	if derr != nil {
		cfg = ""
	}
	cfg = base64.StdEncoding.EncodeToString([]byte(cfg))

	var lastContact *string
	var lastContactFromNow *int
	if a.AccessStatistic.Contacted.Year() > 1 {
		tconv := convertDateJson(a.AccessStatistic.Contacted)
		lastContact = &tconv
		now := time.Now().UTC()
		iconv := int(now.Sub(a.AccessStatistic.Contacted.UTC()).Seconds())
		lastContactFromNow = &iconv
	}

	stat := gqlmodel.AccessStatistic{
		IsConnectd:               a.AccessStatistic.IsConnected,
		IsOverRestrictiveNetwork: a.AccessStatistic.NebulaRestrictiveNetwork,
		LastContact:              lastContact,
		LastContactFromNow:       lastContactFromNow,
	}

	var lastDeviceContact *string
	if a.AccessDevice.Contacted.Year() > 1 {
		tconv := convertDateJson(a.AccessDevice.Contacted)
		lastDeviceContact = &tconv
	}

	// parse OS type from string
	osType := "unknown"
	osData := a.AccessDevice.DeviceOs
	spliOs := strings.Split(a.AccessDevice.DeviceOs, ",")
	if len(spliOs) >= 2 {
		osType = spliOs[0]
		osData = strings.Join(spliOs[1:], ",")
	}

	// prepare OS auto update object
	var osAutoUpdate *gqlmodel.OsAutoUpdate

	if a.AccessDevice.OSAutoUpdate != "" {
		var autoUpd model.OSAutoUpdateType
		if json.Unmarshal([]byte(a.AccessDevice.OSAutoUpdate), &autoUpd) == nil {
			osAutoUpdate = &gqlmodel.OsAutoUpdate{
				OsType:               autoUpd.Type,
				Name:                 autoUpd.Name,
				Version:              autoUpd.Version,
				Description:          autoUpd.Description,
				LastUpdate:           convertDateJson(autoUpd.LastUpdate),
				LastUpdateOutput:     autoUpd.LastUpdateOutput,
				LastUpdateSuccess:    autoUpd.Success,
				SecurityUpdatesCount: autoUpd.SecurityUpdatesCount,
				OtherUpdatesCount:    autoUpd.OtherUpdatesCount,
				SecurityUpdates:      autoUpd.SecurityUpdates,
				OtherUpdates:         autoUpd.OtherUpdates,
			}
		}
	}

	device := gqlmodel.AccessDevice{
		Name:            a.AccessDevice.DeviceName,
		DeviceID:        a.AccessDevice.DeviceID,
		DeviceOSType:    osType,
		DeviceOs:        osData,
		DeviceSWVersion: a.AccessDevice.ClientVersion,
		Contacted:       lastDeviceContact,
		OsAutoUpdate:    osAutoUpdate,
	}

	var lsnrs []*gqlmodel.AccessListener

	for _, v := range a.AccessListeners {
		_lport := v.ListenPort
		_lprot := v.Protocol
		_lhost := v.ForwardHost
		_lhostport := v.ForwardPort
		_ldesc := v.Description
		_lsnr := gqlmodel.AccessListener{
			ListenPort:  &_lport,
			Protocol:    &_lprot,
			ForwardPort: &_lhostport,
			ForwardHost: &_lhost,
			AccessListenerType: &gqlmodel.AccessListenerType{
				ID:    v.AccessListenerType.ID,
				Glyph: v.AccessListenerType.Glyph,
				Name:  v.AccessListenerType.Name,
			},
			Description: &_ldesc,
		}
		lsnrs = append(lsnrs, &_lsnr)
	}

	r := gqlmodel.Access{
		ID:                 a.ID,
		IPAddress:          a.IpAddress,
		Fqdn:               a.FQDN,
		Description:        &a.Description,
		ValidFrom:          convertDateJson(a.ValidFrom),
		ValidTo:            convertDateJson(a.ValidTo),
		Changed:            convertDateJson(a.Changed),
		Config:             &cfg,
		Groups:             grps,
		FwConfig:           &fwconf,
		PunchBack:          *a.NebulaPunchBack,
		RestrictiveNetwork: *a.NebulaRestrictiveNetwork,
		Statistics:         &stat,
		DeviceInfo:         &device,
		Listeners:          lsnrs,
	}
	return r
}

func modelconvUserAccess2Gql(a model.UserAccess) gqlmodel.UserAccess {
	var grps []*gqlmodel.Group
	for _, i := range a.UserAccessGroups {
		g := modelconvGroup2Gql(i.Group)
		grps = append(grps, &g)
	}

	fwconf := modelconvFwConfig2Gql(a.Fwconfig)

	var acc []*gqlmodel.Access
	for _, i := range a.Accesses {
		a := modelconvAccess2Gql(i)
		acc = append(acc, &a)
	}

	uat := modelconvUserAccessTemplate2Gql(a.UserAccessTemplate)

	r := gqlmodel.UserAccess{
		ID:                 a.ID,
		Name:               a.Name,
		Description:        &a.Description,
		Groups:             grps,
		FwConfig:           &fwconf,
		ValidFrom:          convertDateJson(a.ValidFrom),
		ValidTo:            convertDateJson(a.ValidTo),
		Changed:            convertDateJson(a.Changed),
		Accesses:           acc,
		UserAccessTemplate: &uat,
	}
	return r
}

func modelconvUserAccessTemplate2Gql(a model.UserAccessTemplate) gqlmodel.UserAccessTemplate {
	var grps []*gqlmodel.Group
	for _, i := range a.UserAccessTemplateGroups {
		g := modelconvGroup2Gql(i.Group)
		grps = append(grps, &g)
	}
	userat := gqlmodel.UserAccessTemplate{
		ID:          a.ID,
		Name:        a.Name,
		Description: &a.Description,
		ValidFrom:   convertDateJson(a.ValidFrom),
		ValidTo:     convertDateJson(a.ValidTo),
		Changed:     convertDateJson(a.Changed),
	}
	fwc := modelconvFwConfig2Gql(a.Fwconfig)
	userat.FwConfig = &fwc
	userat.Groups = grps
	return userat
}

func modelconvAccessListenerType2Gql(a model.AccessListenerType) gqlmodel.AccessListenerType {
	alt := gqlmodel.AccessListenerType{
		ID:    a.ID,
		Glyph: a.Glyph,
		Name:  a.Name,
	}
	return alt
}

func modelconvFwConfig2Gql(f model.Fwconfig) gqlmodel.FwConfig {
	var fwo []*gqlmodel.FwConfigRule
	var fwi []*gqlmodel.FwConfigRule

	for _, i := range f.Fwconfigouts {
		var grps []*gqlmodel.Group
		for _, j := range i.FwconfigGroups {
			grp := modelconvGroup2Gql(j.Group)
			grps = append(grps, &grp)
		}
		c := gqlmodel.FwConfigRule{Port: i.Port, Proto: i.Proto, Host: i.Host, Groups: grps}
		fwo = append(fwo, &c)
	}
	for _, i := range f.Fwconfigins {
		var grps []*gqlmodel.Group
		for _, j := range i.FwconfigGroups {
			grp := modelconvGroup2Gql(j.Group)
			grps = append(grps, &grp)
		}
		c := gqlmodel.FwConfigRule{Port: i.Port, Proto: i.Proto, Host: i.Host, Groups: grps}
		fwi = append(fwi, &c)
	}

	fwconf := gqlmodel.FwConfig{
		ID:           f.ID,
		Name:         &f.Name,
		Changed:      convertDateJson(f.Changed),
		FwConfigOuts: fwo,
		FwConfigIns:  fwi,
	}
	return fwconf
}

func modelconvGroup2Gql(g model.Group) gqlmodel.Group {
	return gqlmodel.Group{ID: g.ID, Name: g.Name, Description: &g.Description}
}

func modelconvSystemConfig2Gql(c model.SystemConfigDef) gqlmodel.SystemConfig {
	ret := gqlmodel.SystemConfig{
		MaximumCertificateValidity: convertDateJson(c.CA.ValidTo),
		NetworkCidr:                c.Network.CIDR,
	}
	for _, v := range c.Lighthouses {
		ret.Lighthouses = append(ret.Lighthouses,
			&gqlmodel.Lighthouse{PublicIP: v.PublicIP, Port: v.Port, IPAddress: v.Access.IpAddress})
	}
	// AAD config
	lastMessage, _ := model.DacGetKey("AADTASK")
	aadsecret := model.SystemConfig().AADSyncConfig.AADClientSecret
	// strip only 3 chars, so we can see if it is set or not
	if aadsecret != "" {
		aadsecret = aadsecret[:int(math.Min(float64(len(aadsecret)), 3))] + "*********"
	}
	ret.AadConfig = &gqlmodel.AadConfig{
		IsEnabled:             model.SystemConfig().AADSyncConfig.Enabled,
		ClientID:              model.SystemConfig().AADSyncConfig.AADClientID,
		TenantID:              model.SystemConfig().AADSyncConfig.AADTenantID,
		ClientSecret:          aadsecret,
		AdminGroupObjectID:    model.SystemConfig().AADSyncConfig.AdminGroupID,
		LastProcessingMessage: lastMessage,
	}
	// CLI API config
	apikey := model.SystemConfig().CliApiConfig.ApiKey
	if apikey != "" {
		// strip only 3 chars, so we can see if it is set or not
		apikey = apikey[:int(math.Min(float64(len(apikey)), 3))] + "*********"
	}
	ret.CliAPIConfig = &gqlmodel.CliAPIConfig{
		IsEnabled: model.SystemConfig().CliApiConfig.Enabled,
		URL:       _cfg.Server.URI,
		APIKey:    apikey,
	}
	return ret
}

func convertDateJson(t time.Time) string {
	r, _ := json.Marshal(t)
	return strings.Replace(string(r), "\"", "", -1)
}

func convertJsonDate2Date(t string) time.Time {
	var ret time.Time
	json.Unmarshal([]byte("\""+t+"\""), &ret)
	log.Debug("jsonDate inp: ", t)
	log.Debug("jsonDate out: ", ret)
	return ret
}
