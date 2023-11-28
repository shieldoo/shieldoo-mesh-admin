package graph

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	gqlmodel "github.com/shieldoo/shieldoo-mesh-admin/graph/model"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
)

func TestModelconvUserRoles2Gql(t *testing.T) {
	inp := `["USER","ADMINISTRATOR"]`
	outexp := "ADMINISTRATOR,USER"
	d := modelconvUserRoles2Gql(inp)
	outcurr := fmt.Sprintf("%s,%s", *d[0], *d[1])
	if outexp != outcurr {
		t.Fatalf(`modelconvUserRoles2Gql(%+v) returns unexpecxted output. Expected: %s, Current: %s`, inp, outexp, outcurr)
	}
}

func TestModelconvGql2UserRoles(t *testing.T) {
	r1 := "USER"
	r2 := "ADMINISTRATOR"
	inp := []*string{&r1, &r2}
	outexp := `["ADMINISTRATOR","USER"]`
	outcurr := modelconvGql2UserRoles(inp)
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2UserRoles(%+v) returns unexpecxted output. Expected: %s, Current: %s`, inp, outexp, outcurr)
	}
}

func TestModelconvGql2UserEntity(t *testing.T) {
	r1 := "USER"
	r2 := "ADMINISTRATOR"
	desc := "Description"
	orig := "Origin"
	var id int = 10
	inp := []*string{&r1, &r2}
	e := gqlmodel.UserData{
		ID:          &id,
		Upn:         "UPN",
		Name:        "Name",
		Description: &desc,
		Origin:      &orig,
		Roles:       inp,
	}
	m := model.Entity{}
	outexp := `10,UPN,Name,Description,Origin,["ADMINISTRATOR","USER"]`
	modelconvGql2UserEntity(e, &m)
	outcurr := fmt.Sprintf("%d,%s,%s,%s,%s,%s", m.ID, m.UPN, m.Name, m.Description, m.Origin, m.Roles)
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2UserEntity(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGqlInvite2UserEntity(t *testing.T) {
	r1 := "USER"
	r2 := "ADMINISTRATOR"
	desc := "Description"
	var id int = 10
	inp := []*string{&r1, &r2}
	e := gqlmodel.InviteUserData{
		ID:          &id,
		Upn:         "UPN",
		Name:        "Name",
		Description: &desc,
		Roles:       inp,
	}
	m := model.Entity{}
	outexp := `0,UPN,Name,Description,invited,["ADMINISTRATOR","USER"]`
	modelconvGqlInvite2UserEntity(e, &m)
	outcurr := fmt.Sprintf("%d,%s,%s,%s,%s,%s", m.ID, m.UPN, m.Name, m.Description, m.Origin, m.Roles)
	if outexp != outcurr {
		t.Fatalf(`modelconvGqlInvite2UserEntity(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGql2ServerEntity(t *testing.T) {
	desc := "Description"
	name := "Name"
	var id int = 10
	e := gqlmodel.ServerData{
		ID:          &id,
		Name:        name,
		Description: &desc,
	}
	m := model.Entity{}
	outexp := `10,Name,Description`
	modelconvGql2ServerEntity(&e, &m)
	outcurr := fmt.Sprintf("%d,%s,%s", m.ID, m.Name, m.Description)
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2ServerEntity(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGqlUserAccess2UserAccess(t *testing.T) {
	desc := "Description"
	ids := []int{1, 2, 3}
	var id int = 10
	now := time.Now().UTC()
	nows := convertDateJson(now)
	e := gqlmodel.UserAccessData{
		ID:          &id,
		Name:        "Name",
		Description: &desc,
		GroupsIds:   ids,
		FwConfigID:  102,
		ValidTo:     nows,
		EntityID:    1003,
	}
	m := model.UserAccess{}
	outexp := fmt.Sprintf(`10,Name,Description,102,1003,[1 10 2 10 3 10],%s`, now.GoString())
	modelconvGqlUserAccess2UserAccess(e, &m)
	outcurrgrps := []int{}
	for _, v := range m.UserAccessGroups {
		outcurrgrps = append(outcurrgrps, v.GroupID)
		outcurrgrps = append(outcurrgrps, v.UserAccessID)
	}
	outcurr := fmt.Sprintf("%d,%s,%s,%d,%d,%+v,%s", m.ID, m.Name, m.Description, m.FwconfigID, m.EntityID, outcurrgrps, m.ValidTo.GoString())
	if outexp != outcurr {
		t.Fatalf(`modelconvGqlUserAccess2UserAccess(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGqlServerAccess2Access(t *testing.T) {
	desc := "Description"
	ids := []int{1, 2, 3}
	ipaddr := "1.2.3.4"
	var lsnrLPort int = 1111
	var lsnrFPort int = 2222
	lsnrProtocol := "tcp"
	lsnrHost := "testhost"
	lsnr := gqlmodel.AccessListenerData{
		ListenPort:           lsnrLPort,
		Protocol:             lsnrProtocol,
		ForwardPort:          lsnrFPort,
		ForwardHost:          lsnrHost,
		AccessListenerTypeID: 999,
	}
	lsnrs := []*gqlmodel.AccessListenerData{&lsnr}
	now := time.Now().UTC()
	nows := convertDateJson(now)
	e := gqlmodel.ServerAccessData{
		Description:        &desc,
		GroupsIds:          ids,
		FwConfigID:         102,
		ValidTo:            nows,
		IPAddress:          &ipaddr,
		PunchBack:          true,
		RestrictiveNetwork: true,
		Listeners:          lsnrs,
	}
	m := model.Access{}
	outexp := fmt.Sprintf(`10,,Description,102,1003,[1 10 2 10 3 10],10,1111,tcp,testhost,2222,999,%s`, now.GoString())
	modelconvGqlServerAccess2Access(1003, 10, e, "fqdn", true, &m)
	outcurrgrps := []int{}
	for _, v := range m.AccessGroups {
		outcurrgrps = append(outcurrgrps, v.GroupID)
		outcurrgrps = append(outcurrgrps, v.AccessID)
	}
	outlsnrs := fmt.Sprintf("%d,%d,%s,%s,%d,%d", m.AccessListeners[0].AccessID, m.AccessListeners[0].ListenPort, m.AccessListeners[0].Protocol, m.AccessListeners[0].ForwardHost, m.AccessListeners[0].ForwardPort, m.AccessListeners[0].AccessListenerTypeID)
	outcurr := fmt.Sprintf("%d,%s,%s,%d,%d,%+v,%s,%s", m.ID, m.Name, m.Description, m.FwconfigID, m.EntityID, outcurrgrps, outlsnrs, m.ValidTo.GoString())
	if outexp != outcurr {
		t.Fatalf(`modelconvGqlServerAccess2Access(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGql2Group(t *testing.T) {
	desc := "Description"
	var id int = 10
	e := gqlmodel.GroupData{
		ID:          &id,
		Name:        "Name",
		Description: &desc,
	}
	m := model.Group{}
	outexp := `10,Name,Description`
	modelconvGql2Group(e, &m)
	outcurr := fmt.Sprintf("%d,%s,%s", m.ID, m.Name, m.Description)
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2Group(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGql2UserAccessTemplate(t *testing.T) {
	desc := "Description"
	var id int = 10
	ids := []int{1, 2, 3}
	now := time.Now().UTC()
	nows := convertDateJson(now)
	e := gqlmodel.UserAccessTemplateData{
		ID:          &id,
		Name:        "Name",
		Description: &desc,
		GroupsIds:   ids,
		FwConfigID:  102,
		ValidTo:     nows,
		Deleted:     true,
	}
	m := model.UserAccessTemplate{}
	outexp := fmt.Sprintf(`10,Name,Description,true,102,[1 10 2 10 3 10],%+v`, now.GoString())
	modelconvGql2UserAccessTemplate(e, &m)
	outcurrgrps := []int{}
	for _, v := range m.UserAccessTemplateGroups {
		outcurrgrps = append(outcurrgrps, v.GroupID)
		outcurrgrps = append(outcurrgrps, v.UserAccessTemplateID)
	}
	outcurr := fmt.Sprintf("%d,%s,%s,%v,%d,%+v,%s", m.ID, m.Name, m.Description, *m.Deleted, m.FwconfigID, outcurrgrps, m.ValidTo.GoString())
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2UserAccessTemplate(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGql2Fwconfig(t *testing.T) {
	name := "Name"
	var id int = 10
	var fwIGid int = 222
	var fwOGid int = 333
	fwIG := gqlmodel.GroupData{ID: &fwIGid, Name: "test"}
	fwI := gqlmodel.FwConfigRuleData{Port: "1111", Proto: "tcp", Host: "host", Groups: []*gqlmodel.GroupData{&fwIG}}
	fwOG := gqlmodel.GroupData{ID: &fwOGid, Name: "test"}
	fwO := gqlmodel.FwConfigRuleData{Port: "2222", Proto: "udp", Host: "group", Groups: []*gqlmodel.GroupData{&fwOG}}
	e := gqlmodel.FwConfigData{
		ID:           &id,
		Name:         &name,
		FwConfigOuts: []*gqlmodel.FwConfigRuleData{&fwO},
		FwConfigIns:  []*gqlmodel.FwConfigRuleData{&fwI},
	}
	m := model.Fwconfig{}
	outexp := `10,Name,2222,udp,group,333,1111,tcp,host,222`
	modelconvGql2Fwconfig(e, &m)
	outcurr := fmt.Sprintf("%d,%s,%s,%s,%s,%d,%s,%s,%s,%d",
		m.ID, m.Name,
		m.Fwconfigouts[0].Port, m.Fwconfigouts[0].Proto, m.Fwconfigouts[0].Host, m.Fwconfigouts[0].FwconfigGroups[0].GroupID,
		m.Fwconfigins[0].Port, m.Fwconfigins[0].Proto, m.Fwconfigins[0].Host, m.Fwconfigins[0].FwconfigGroups[0].GroupID)
	if outexp != outcurr {
		t.Fatalf(`modelconvGql2Fwconfig(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestUSERmodelconvEntity2Gql(t *testing.T) {
	m := model.Entity{
		Base:        model.Base{ID: 10},
		EntityType:  model.ENTITY_USER,
		UPN:         "upn",
		Name:        "name",
		Origin:      "origin",
		Roles:       `["USER"]`,
		Description: "description",
		Secret:      "secret",
		UserAccesses: []model.UserAccess{
			{
				Base:                 model.Base{ID: 101},
				Name:                 "acc-name",
				Description:          "acc-description",
				UserAccessTemplateID: 1001,
				UserAccessTemplate: model.UserAccessTemplate{
					Base:        model.Base{ID: 1001},
					Name:        "template-name",
					Description: "template-description",
					UserAccessTemplateGroups: []model.UserAccessTemplateGroup{
						{
							Base:                 model.Base{ID: 11},
							UserAccessTemplateID: 1001,
							GroupID:              10001,
							Group: model.Group{
								Base:        model.Base{ID: 10001},
								Name:        "group-name",
								Description: "group-description",
							},
						},
					},
					FwconfigID: 1002,
					Fwconfig: model.Fwconfig{
						Base: model.Base{ID: 1002},
						Name: "fw-name",
						Fwconfigouts: []model.Fwconfigout{
							{
								Base:       model.Base{ID: 100201},
								FwconfigID: 1002,
								Port:       "222",
								Proto:      "tcp",
								Host:       "host",
								FwconfigGroups: []model.FwconfigoutGroup{
									{
										Base:          model.Base{ID: 100202},
										FwconfigoutID: 100201,
										GroupID:       100203,
										Group: model.Group{
											Base:        model.Base{ID: 100203},
											Name:        "fwoutgroup-name",
											Description: "fwoutgroup-desc",
										},
									},
								},
							},
						},
						Fwconfigins: []model.Fwconfigin{
							{
								Base:       model.Base{ID: 100211},
								FwconfigID: 1002,
								Port:       "333",
								Proto:      "udp",
								Host:       "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Base:         model.Base{ID: 100212},
										FwconfiginID: 1002,
										GroupID:      100213,
										Group: model.Group{
											Base:        model.Base{ID: 100213},
											Name:        "fwingroup-name",
											Description: "fwingroup-desc",
										},
									},
								},
							},
						},
					},
					ValidFrom: time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC),
					ValidTo:   time.Date(2022, 11, 12, 13, 14, 15, 16, time.UTC),
				},
				UserAccessGroups: []model.UserAccessGroup{
					{
						Base:         model.Base{ID: 2000},
						UserAccessID: 101,
						GroupID:      200001,
						Group: model.Group{
							Base:        model.Base{ID: 200001},
							Name:        "ua-test",
							Description: "ua-desc",
						},
					},
				},
				FwconfigID: 2002,
				Fwconfig: model.Fwconfig{
					Base: model.Base{ID: 2002},
					Name: "fw-name2",
					Fwconfigouts: []model.Fwconfigout{
						{
							Base:       model.Base{ID: 200201},
							FwconfigID: 2002,
							Port:       "2222",
							Proto:      "tcp",
							Host:       "2host",
							FwconfigGroups: []model.FwconfigoutGroup{
								{
									Base:          model.Base{ID: 200202},
									FwconfigoutID: 200201,
									GroupID:       200203,
									Group: model.Group{
										Base:        model.Base{ID: 200203},
										Name:        "2fwoutgroup-name",
										Description: "2fwoutgroup-desc",
									},
								},
							},
						},
					},
					Fwconfigins: []model.Fwconfigin{
						{
							Base:       model.Base{ID: 200211},
							FwconfigID: 2002,
							Port:       "2333",
							Proto:      "udp",
							Host:       "group",
							FwconfigGroups: []model.FwconfiginGroup{
								{
									Base:         model.Base{ID: 200212},
									FwconfiginID: 2002,
									GroupID:      200213,
									Group: model.Group{
										Base:        model.Base{ID: 200213},
										Name:        "2fwingroup-name",
										Description: "2fwingroup-desc",
									},
								},
							},
						},
					},
				},
				EntityID:  10,
				ValidFrom: time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC),
				ValidTo:   time.Date(2022, 11, 12, 13, 14, 15, 16, time.UTC),
				Secret:    "secret",
			},
		},
	}
	outexp := `{"id":10,"upn":"upn","name":"name","description":"description","userAccesses":[{"id":101,"name":"acc-name","description":"acc-description","groups":[{"id":200001,"name":"ua-test","description":"ua-desc"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2000-01-02T03:04:05.000000006Z","validTo":"2022-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z","userAccessTemplate":{"id":1001,"name":"template-name","description":"template-description","groups":[{"id":10001,"name":"group-name","description":"group-description"}],"fwConfig":{"id":1002,"name":"fw-name","fwConfigOuts":[{"port":"222","proto":"tcp","host":"host","groups":[{"id":100203,"name":"fwoutgroup-name","description":"fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"333","proto":"udp","host":"group","groups":[{"id":100213,"name":"fwingroup-name","description":"fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2000-01-02T03:04:05.000000006Z","validTo":"2022-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z"},"accesses":null,"serversForAccess":null}],"origin":"origin","roles":["USER"]}`
	e := modelconvEntityUser2Gql(m)
	//outcurr := fmt.Sprintf("%#v", e)
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvEntityUser2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestSERVERmodelconvEntity2Gql(t *testing.T) {
	_bool := true
	m := model.Entity{
		Base:        model.Base{ID: 10},
		EntityType:  model.ENTITY_SERVER,
		UPN:         "name",
		Name:        "name",
		Origin:      "",
		Roles:       ``,
		Description: "description",
		Secret:      "secret",
		Accesses: []model.Access{
			{
				Base:        model.Base{ID: 101},
				Name:        "acc-name",
				Description: "acc-description",
				IpAddress:   "1.2.3.4",
				FQDN:        "name",
				AccessGroups: []model.AccessGroup{
					{
						Base:     model.Base{ID: 2000},
						AccessID: 101,
						GroupID:  200001,
						Group: model.Group{
							Base:        model.Base{ID: 200001},
							Name:        "ua-test",
							Description: "ua-desc",
						},
					},
				},
				FwconfigID: 2002,
				Fwconfig: model.Fwconfig{
					Base: model.Base{ID: 2002},
					Name: "fw-name2",
					Fwconfigouts: []model.Fwconfigout{
						{
							Base:       model.Base{ID: 200201},
							FwconfigID: 2002,
							Port:       "2222",
							Proto:      "tcp",
							Host:       "2host",
							FwconfigGroups: []model.FwconfigoutGroup{
								{
									Base:          model.Base{ID: 200202},
									FwconfigoutID: 200201,
									GroupID:       200203,
									Group: model.Group{
										Base:        model.Base{ID: 200203},
										Name:        "2fwoutgroup-name",
										Description: "2fwoutgroup-desc",
									},
								},
							},
						},
					},
					Fwconfigins: []model.Fwconfigin{
						{
							Base:       model.Base{ID: 200211},
							FwconfigID: 2002,
							Port:       "2333",
							Proto:      "udp",
							Host:       "group",
							FwconfigGroups: []model.FwconfiginGroup{
								{
									Base:         model.Base{ID: 200212},
									FwconfiginID: 2002,
									GroupID:      200213,
									Group: model.Group{
										Base:        model.Base{ID: 200213},
										Name:        "2fwingroup-name",
										Description: "2fwingroup-desc",
									},
								},
							},
						},
					},
				},
				EntityID:                 10,
				ValidFrom:                time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC),
				ValidTo:                  time.Date(2022, 11, 12, 13, 14, 15, 16, time.UTC),
				Secret:                   "secret",
				NebulaPunchBack:          &_bool,
				NebulaRestrictiveNetwork: &_bool,
			},
		},
	}
	outexp := `{"id":10,"name":"name","allowAutoUpdate":false,"description":"description","access":{"id":101,"name":"","ipAddress":"1.2.3.4","fqdn":"name","additionalHostnames":null,"description":"acc-description","groups":[{"id":200001,"name":"ua-test","description":"ua-desc"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2000-01-02T03:04:05.000000006Z","validTo":"2022-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z","listeners":null,"config":"CONFIG","punchBack":true,"restrictiveNetwork":true,"statistics":{"isConnectd":null,"isOverRestrictiveNetwork":null,"lastContact":null,"lastContactFromNow":null},"deviceInfo":{"name":"","deviceId":"","deviceOSType":"unknown","deviceOS":"","deviceSWVersion":"","contacted":null,"osAutoUpdate":null}},"serverOSAutoUpdatePolicy":{"osAutoUpdateEnabled":false,"osAutoUpdateHour":0,"securityAutoUpdateEnabled":false,"allAutoUpdateEnabled":false,"restartAfterUpdate":false}}`
	cfg := utils.Config{}
	cfg.Server.URI = "http://test"
	model.TestInit(&cfg)
	e := modelconvEntityServer2Gql(m)
	// cleanup config data (nondetrerministic)
	if e.Access.Config != nil && len(*e.Access.Config) > 32 {
		x := "CONFIG"
		e.Access.Config = &x
	}
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvEntityServer2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvAccess2Gql(t *testing.T) {
	_bool := true
	m := model.Access{
		Base:        model.Base{ID: 101},
		Name:        "acc-name",
		Description: "acc-description",
		IpAddress:   "1.2.3.4",
		FQDN:        "fqdn",
		AccessGroups: []model.AccessGroup{
			{
				Base:     model.Base{ID: 2000},
				AccessID: 101,
				GroupID:  200001,
				Group: model.Group{
					Base:        model.Base{ID: 200001},
					Name:        "ua-test",
					Description: "ua-desc",
				},
			},
		},
		FwconfigID: 2002,
		Fwconfig: model.Fwconfig{
			Base: model.Base{ID: 2002},
			Name: "fw-name2",
			Fwconfigouts: []model.Fwconfigout{
				{
					Base:       model.Base{ID: 200201},
					FwconfigID: 2002,
					Port:       "2222",
					Proto:      "tcp",
					Host:       "2host",
					FwconfigGroups: []model.FwconfigoutGroup{
						{
							Base:          model.Base{ID: 200202},
							FwconfigoutID: 200201,
							GroupID:       200203,
							Group: model.Group{
								Base:        model.Base{ID: 200203},
								Name:        "2fwoutgroup-name",
								Description: "2fwoutgroup-desc",
							},
						},
					},
				},
			},
			Fwconfigins: []model.Fwconfigin{
				{
					Base:       model.Base{ID: 200211},
					FwconfigID: 2002,
					Port:       "2333",
					Proto:      "udp",
					Host:       "group",
					FwconfigGroups: []model.FwconfiginGroup{
						{
							Base:         model.Base{ID: 200212},
							FwconfiginID: 2002,
							GroupID:      200213,
							Group: model.Group{
								Base:        model.Base{ID: 200213},
								Name:        "2fwingroup-name",
								Description: "2fwingroup-desc",
							},
						},
					},
				},
			},
		},
		EntityID:                 10,
		ValidFrom:                time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC),
		ValidTo:                  time.Date(2022, 11, 12, 13, 14, 15, 16, time.UTC),
		Secret:                   "secret",
		NebulaPunchBack:          &_bool,
		NebulaRestrictiveNetwork: &_bool,
		AccessListeners: []model.AccessListener{
			{
				Base:                 model.Base{ID: 200221},
				AccessID:             101,
				ListenPort:           900,
				Protocol:             "tcp",
				ForwardPort:          901,
				ForwardHost:          "fwhost",
				AccessListenerTypeID: 999,
				AccessListenerType: model.AccessListenerType{
					Base:  model.Base{ID: 999},
					Glyph: "glyph",
					Name:  "glyph-name",
				},
				Description: "acl-desc",
			},
		},
		AccessStatistic: model.AccessStatistic{
			AccessID:                 101,
			IsConnected:              &_bool,
			NebulaRestrictiveNetwork: &_bool,
			Contacted:                time.Date(2000, 1, 2, 3, 34, 35, 36, time.UTC),
		},
		AccessDevice: model.AccessDevice{
			AccessID:      101,
			DeviceName:    "devicename",
			DeviceID:      "deviceid",
			DeviceOs:      "linux,deviceos,v123",
			ClientVersion: "123456",
			Contacted:     time.Date(2000, 1, 2, 3, 44, 45, 46, time.UTC),
		},
	}
	outexp := `{"id":101,"name":"","ipAddress":"1.2.3.4","fqdn":"fqdn","additionalHostnames":null,"description":"acc-description","groups":[{"id":200001,"name":"ua-test","description":"ua-desc"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2000-01-02T03:04:05.000000006Z","validTo":"2022-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z","listeners":[{"listenPort":900,"protocol":"tcp","forwardPort":901,"forwardHost":"fwhost","accessListenerType":{"id":999,"glyph":"glyph","name":"glyph-name"},"description":"acl-desc"}],"config":"CONFIG","punchBack":true,"restrictiveNetwork":true,"statistics":{"isConnectd":true,"isOverRestrictiveNetwork":true,"lastContact":"2000-01-02T03:34:35.000000036Z","lastContactFromNow":7777777},"deviceInfo":{"name":"devicename","deviceId":"deviceid","deviceOSType":"linux","deviceOS":"deviceos,v123","deviceSWVersion":"123456","contacted":"2000-01-02T03:44:45.000000046Z","osAutoUpdate":null}}`
	cfg := utils.Config{}
	cfg.Server.URI = "http://test"
	model.TestInit(&cfg)
	e := modelconvAccess2Gql(m)
	// cleanup config data (nondetrerministic)
	if e.Config != nil && len(*e.Config) > 32 {
		x := "CONFIG"
		e.Config = &x
	}
	if *e.Statistics.LastContactFromNow != 0 {
		_i := 7777777
		e.Statistics.LastContactFromNow = &_i
	}
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvAccess2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvUserAccess2Gql(t *testing.T) {
	m := model.UserAccess{
		Base:        model.Base{ID: 101},
		Name:        "acc-name",
		Description: "acc-description",
		UserAccessGroups: []model.UserAccessGroup{
			{
				Base:         model.Base{ID: 2000},
				UserAccessID: 101,
				GroupID:      200001,
				Group: model.Group{
					Base:        model.Base{ID: 200001},
					Name:        "ua-test",
					Description: "ua-desc",
				},
			},
		},
		FwconfigID: 2002,
		Fwconfig: model.Fwconfig{
			Base: model.Base{ID: 2002},
			Name: "fw-name2",
			Fwconfigouts: []model.Fwconfigout{
				{
					Base:       model.Base{ID: 200201},
					FwconfigID: 2002,
					Port:       "2222",
					Proto:      "tcp",
					Host:       "2host",
					FwconfigGroups: []model.FwconfigoutGroup{
						{
							Base:          model.Base{ID: 200202},
							FwconfigoutID: 200201,
							GroupID:       200203,
							Group: model.Group{
								Base:        model.Base{ID: 200203},
								Name:        "2fwoutgroup-name",
								Description: "2fwoutgroup-desc",
							},
						},
					},
				},
			},
			Fwconfigins: []model.Fwconfigin{
				{
					Base:       model.Base{ID: 200211},
					FwconfigID: 2002,
					Port:       "2333",
					Proto:      "udp",
					Host:       "group",
					FwconfigGroups: []model.FwconfiginGroup{
						{
							Base:         model.Base{ID: 200212},
							FwconfiginID: 2002,
							GroupID:      200213,
							Group: model.Group{
								Base:        model.Base{ID: 200213},
								Name:        "2fwingroup-name",
								Description: "2fwingroup-desc",
							},
						},
					},
				},
			},
		},
		EntityID:             10,
		ValidFrom:            time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC),
		ValidTo:              time.Date(2022, 11, 12, 13, 14, 15, 16, time.UTC),
		Secret:               "secret",
		UserAccessTemplateID: 9999,
		UserAccessTemplate: model.UserAccessTemplate{
			Base:        model.Base{ID: 9999},
			Name:        "template",
			Description: "desc",
			UserAccessTemplateGroups: []model.UserAccessTemplateGroup{
				{
					Base:                 model.Base{ID: 987},
					UserAccessTemplateID: 9999,
					GroupID:              999,
					Group: model.Group{
						Base:        model.Base{ID: 999},
						Name:        "template-grp",
						Description: "desc-template",
					},
				},
			},
			FwconfigID: 2002,
			Fwconfig: model.Fwconfig{
				Base: model.Base{ID: 2002},
				Name: "fw-name2",
				Fwconfigouts: []model.Fwconfigout{
					{
						Base:       model.Base{ID: 200201},
						FwconfigID: 2002,
						Port:       "2222",
						Proto:      "tcp",
						Host:       "2host",
						FwconfigGroups: []model.FwconfigoutGroup{
							{
								Base:          model.Base{ID: 200202},
								FwconfigoutID: 200201,
								GroupID:       200203,
								Group: model.Group{
									Base:        model.Base{ID: 200203},
									Name:        "2fwoutgroup-name",
									Description: "2fwoutgroup-desc",
								},
							},
						},
					},
				},
				Fwconfigins: []model.Fwconfigin{
					{
						Base:       model.Base{ID: 200211},
						FwconfigID: 2002,
						Port:       "2333",
						Proto:      "udp",
						Host:       "group",
						FwconfigGroups: []model.FwconfiginGroup{
							{
								Base:         model.Base{ID: 200212},
								FwconfiginID: 2002,
								GroupID:      200213,
								Group: model.Group{
									Base:        model.Base{ID: 200213},
									Name:        "2fwingroup-name",
									Description: "2fwingroup-desc",
								},
							},
						},
					},
				},
			},
			ValidFrom: time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC),
			ValidTo:   time.Date(2012, 11, 12, 13, 14, 15, 16, time.UTC),
		},
	}
	outexp := `{"id":101,"name":"acc-name","description":"acc-description","groups":[{"id":200001,"name":"ua-test","description":"ua-desc"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2000-01-02T03:04:05.000000006Z","validTo":"2022-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z","userAccessTemplate":{"id":9999,"name":"template","description":"desc","groups":[{"id":999,"name":"template-grp","description":"desc-template"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2011-01-02T03:04:05.000000006Z","validTo":"2012-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z"},"accesses":null,"serversForAccess":null}`
	e := modelconvUserAccess2Gql(m)
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvUserAccess2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvUserAccessTemplate2Gql(t *testing.T) {
	m := model.UserAccessTemplate{
		Base:        model.Base{ID: 9999},
		Name:        "template",
		Description: "desc",
		UserAccessTemplateGroups: []model.UserAccessTemplateGroup{
			{
				Base:                 model.Base{ID: 987},
				UserAccessTemplateID: 9999,
				GroupID:              999,
				Group: model.Group{
					Base:        model.Base{ID: 999},
					Name:        "template-grp",
					Description: "desc-template",
				},
			},
		},
		FwconfigID: 2002,
		Fwconfig: model.Fwconfig{
			Base: model.Base{ID: 2002},
			Name: "fw-name2",
			Fwconfigouts: []model.Fwconfigout{
				{
					Base:       model.Base{ID: 200201},
					FwconfigID: 2002,
					Port:       "2222",
					Proto:      "tcp",
					Host:       "2host",
					FwconfigGroups: []model.FwconfigoutGroup{
						{
							Base:          model.Base{ID: 200202},
							FwconfigoutID: 200201,
							GroupID:       200203,
							Group: model.Group{
								Base:        model.Base{ID: 200203},
								Name:        "2fwoutgroup-name",
								Description: "2fwoutgroup-desc",
							},
						},
					},
				},
			},
			Fwconfigins: []model.Fwconfigin{
				{
					Base:       model.Base{ID: 200211},
					FwconfigID: 2002,
					Port:       "2333",
					Proto:      "udp",
					Host:       "group",
					FwconfigGroups: []model.FwconfiginGroup{
						{
							Base:         model.Base{ID: 200212},
							FwconfiginID: 2002,
							GroupID:      200213,
							Group: model.Group{
								Base:        model.Base{ID: 200213},
								Name:        "2fwingroup-name",
								Description: "2fwingroup-desc",
							},
						},
					},
				},
			},
		},
		ValidFrom: time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC),
		ValidTo:   time.Date(2012, 11, 12, 13, 14, 15, 16, time.UTC),
	}
	outexp := `{"id":9999,"name":"template","description":"desc","groups":[{"id":999,"name":"template-grp","description":"desc-template"}],"fwConfig":{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"},"validFrom":"2011-01-02T03:04:05.000000006Z","validTo":"2012-11-12T13:14:15.000000016Z","changed":"0001-01-01T00:00:00Z"}`
	e := modelconvUserAccessTemplate2Gql(m)
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvUserAccessTemplate2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvAccessListenerType2Gql(t *testing.T) {
	m := model.AccessListenerType{
		Base:  model.Base{ID: 111},
		Name:  "name",
		Glyph: "glyph",
	}
	outexp := `111,name,glyph`
	e := modelconvAccessListenerType2Gql(m)
	outcurr := fmt.Sprintf("%d,%s,%s", e.ID, e.Name, e.Glyph)
	if outexp != outcurr {
		t.Fatalf(`modelconvAccessListenerType2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvFwConfig2Gql(t *testing.T) {
	m := model.Fwconfig{
		Base: model.Base{ID: 2002},
		Name: "fw-name2",
		Fwconfigouts: []model.Fwconfigout{
			{
				Base:       model.Base{ID: 200201},
				FwconfigID: 2002,
				Port:       "2222",
				Proto:      "tcp",
				Host:       "2host",
				FwconfigGroups: []model.FwconfigoutGroup{
					{
						Base:          model.Base{ID: 200202},
						FwconfigoutID: 200201,
						GroupID:       200203,
						Group: model.Group{
							Base:        model.Base{ID: 200203},
							Name:        "2fwoutgroup-name",
							Description: "2fwoutgroup-desc",
						},
					},
				},
			},
		},
		Fwconfigins: []model.Fwconfigin{
			{
				Base:       model.Base{ID: 200211},
				FwconfigID: 2002,
				Port:       "2333",
				Proto:      "udp",
				Host:       "group",
				FwconfigGroups: []model.FwconfiginGroup{
					{
						Base:         model.Base{ID: 200212},
						FwconfiginID: 2002,
						GroupID:      200213,
						Group: model.Group{
							Base:        model.Base{ID: 200213},
							Name:        "2fwingroup-name",
							Description: "2fwingroup-desc",
						},
					},
				},
			},
		},
	}
	outexp := `{"id":2002,"name":"fw-name2","fwConfigOuts":[{"port":"2222","proto":"tcp","host":"2host","groups":[{"id":200203,"name":"2fwoutgroup-name","description":"2fwoutgroup-desc"}]}],"fwConfigIns":[{"port":"2333","proto":"udp","host":"group","groups":[{"id":200213,"name":"2fwingroup-name","description":"2fwingroup-desc"}]}],"changed":"0001-01-01T00:00:00Z"}`
	e := modelconvFwConfig2Gql(m)
	outcurr, _ := json.Marshal(e)
	outcurrs := string(outcurr)
	if outexp != outcurrs {
		t.Fatalf(`modelconvFwConfig2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvGroup2Gql(t *testing.T) {
	m := model.Group{
		Base:        model.Base{ID: 111},
		Name:        "name",
		Description: "desc",
	}
	outexp := `111,name,desc`
	e := modelconvGroup2Gql(m)
	outcurr := fmt.Sprintf("%d,%s,%s", e.ID, e.Name, *e.Description)
	if outexp != outcurr {
		t.Fatalf(`modelconvGroup2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvEntityUser2Gql(t *testing.T) {
	m := model.Entity{
		Base:        model.Base{ID: 111},
		EntityType:  model.ENTITY_USER,
		UPN:         "upn",
		Origin:      "origin",
		Roles:       `["USER"]`,
		Name:        "name",
		Description: "desc",
	}
	outexp := `111,name,desc,upn,origin,USER`
	e := modelconvEntityUser2Gql(m)
	outcurr := fmt.Sprintf("%d,%s,%s,%s,%s,%s", e.ID, e.Name, *e.Description, e.Upn, *e.Origin, *e.Roles[0])
	if outexp != outcurr {
		t.Fatalf(`modelconvEntityUser2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestModelconvEntityServer2Gql(t *testing.T) {
	m := model.Entity{
		Base:        model.Base{ID: 111},
		EntityType:  model.ENTITY_USER,
		Name:        "name",
		Description: "desc",
	}
	outexp := `111,name,desc`
	e := modelconvEntityServer2Gql(m)
	outcurr := fmt.Sprintf("%d,%s,%s", e.ID, e.Name, *e.Description)
	if outexp != outcurr {
		t.Fatalf(`modelconvEntityServer2Gql(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestConvertDateJson(t *testing.T) {
	m := time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC)
	outexp := `2011-01-02T03:04:05.000000006Z`
	e := convertDateJson(m)
	outcurr := e
	if outexp != outcurr {
		t.Fatalf(`convertDateJson(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}

func TestConvertJsonDate2Date(t *testing.T) {
	m := `2011-01-02T03:04:05.000000006Z`
	outexp := time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC).GoString()
	e := convertJsonDate2Date(m)
	outcurr := e.GoString()
	if outexp != outcurr {
		t.Fatalf(`convertJsonDate2Date(%+v,&m) returns unexpecxted output. Expected: %s, Current: %s`, e, outexp, outcurr)
	}
}
