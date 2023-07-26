package graph

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	gqlmodel "github.com/shieldoo/shieldoo-mesh-admin/graph/model"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
)

func TestResolveUserAccessToServerDependency(t *testing.T) {

	ua := gqlmodel.UserAccess{
		ValidTo: convertDateJson(time.Now().Add(time.Hour * 10000)),
		Groups: []*gqlmodel.Group{
			{Name: "grp1"},
		},
	}

	srvrs := []model.Entity{
		{
			UPN:         "srv1-fqdn",
			Name:        "srv1-fqdn",
			Description: "some description 1",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "any",
								Proto: "any",
								Host:  "any",
							},
						},
					},
					IpAddress: "1.1.1.1",
					FQDN:      "srv1-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "+description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "+description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
		{
			UPN:         "srv2-fqdn",
			Name:        "srv2-fqdn",
			Description: "some description 2",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(-1 * time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "any",
								Proto: "any",
								Host:  "any",
							},
						},
					},
					IpAddress: "1.1.1.2",
					FQDN:      "srv2-fqdn",
				},
			},
		},
		{
			UPN:         "srv3-fqdn",
			Name:        "srv3-fqdn",
			Description: "some description 3",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "any",
								Proto: "any",
								Host:  "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Group: model.Group{
											Name: "grp0",
										},
									},
									{
										Group: model.Group{
											Name: "grp1",
										},
									},
									{
										Group: model.Group{
											Name: "grp2",
										},
									},
								},
							},
						},
					},
					IpAddress: "1.1.1.3",
					FQDN:      "srv3-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
		{
			UPN:         "srv4-fqdn",
			Name:        "srv4-fqdn",
			Description: "some description 4",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "1002",
								Proto: "tcp",
								Host:  "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Group: model.Group{
											Name: "grp0",
										},
									},
									{
										Group: model.Group{
											Name: "grp1",
										},
									},
									{
										Group: model.Group{
											Name: "grp2",
										},
									},
								},
							},
						},
					},
					IpAddress: "1.1.1.4",
					FQDN:      "srv4-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
		{
			UPN:         "srv5-fqdn",
			Name:        "srv5-fqdn",
			Description: "some description 5",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "1002-9999",
								Proto: "tcp",
								Host:  "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Group: model.Group{
											Name: "grp0",
										},
									},
									{
										Group: model.Group{
											Name: "grp1",
										},
									},
									{
										Group: model.Group{
											Name: "grp2",
										},
									},
								},
							},
						},
					},
					IpAddress: "1.1.1.5",
					FQDN:      "srv5-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
		{
			UPN:         "srv6-fqdn",
			Name:        "srv6-fqdn",
			Description: "some description 6",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "2000-3000",
								Proto: "tcp",
								Host:  "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Group: model.Group{
											Name: "grp0",
										},
									},
									{
										Group: model.Group{
											Name: "grp1",
										},
									},
									{
										Group: model.Group{
											Name: "grp2",
										},
									},
								},
							},
						},
					},
					IpAddress: "1.1.1.6",
					FQDN:      "srv6-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
		{
			UPN:         "srv7-fqdn",
			Name:        "srv7-fqdn",
			Description: "some description 7",
			Accesses: []model.Access{
				{
					ValidTo: time.Now().Add(time.Hour * 10000),
					Fwconfig: model.Fwconfig{
						Fwconfigins: []model.Fwconfigin{
							{
								Port:  "any",
								Proto: "icmp",
								Host:  "group",
								FwconfigGroups: []model.FwconfiginGroup{
									{
										Group: model.Group{
											Name: "grp0",
										},
									},
									{
										Group: model.Group{
											Name: "grp1",
										},
									},
									{
										Group: model.Group{
											Name: "grp2",
										},
									},
								},
							},
						},
					},
					IpAddress: "1.1.1.7",
					FQDN:      "srv7-fqdn",
					AccessListeners: []model.AccessListener{
						{
							ListenPort:  1001,
							Protocol:    "tcp",
							ForwardPort: 10001,
							ForwardHost: "fwhost1",
							Description: "description-listener-1",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 1},
								Glyph: "glyph1",
								Name:  "name1",
							},
						},
						{
							ListenPort:  1002,
							Protocol:    "tcp",
							ForwardPort: 10002,
							ForwardHost: "fwhost2",
							Description: "description-listener-2",
							AccessListenerType: model.AccessListenerType{
								Base:  model.Base{ID: 2},
								Glyph: "glyph2",
								Name:  "name2",
							},
						},
					},
				},
			},
		},
	}

	outexp := `[
  {
    "name": "srv1-fqdn",
    "ipAddress": "1.1.1.1",
    "description": "some description 1",
    "listeners": [
      {
        "listenPort": 1001,
        "protocol": "tcp",
        "forwardPort": 10001,
        "forwardHost": "fwhost1",
        "accessListenerType": {
          "id": 1,
          "glyph": "glyph1",
          "name": "name1"
        },
        "description": "+description-listener-1"
      },
      {
        "listenPort": 1002,
        "protocol": "tcp",
        "forwardPort": 10002,
        "forwardHost": "fwhost2",
        "accessListenerType": {
          "id": 2,
          "glyph": "glyph2",
          "name": "name2"
        },
        "description": "+description-listener-2"
      }
    ],
    "statistics": {
      "isConnectd": null,
      "isOverRestrictiveNetwork": null,
      "lastContact": null,
      "lastContactFromNow": null
    }
  },
  {
    "name": "srv3-fqdn",
    "ipAddress": "1.1.1.3",
    "description": "some description 3",
    "listeners": [
      {
        "listenPort": 1001,
        "protocol": "tcp",
        "forwardPort": 10001,
        "forwardHost": "fwhost1",
        "accessListenerType": {
          "id": 1,
          "glyph": "glyph1",
          "name": "name1"
        },
        "description": "description-listener-1"
      },
      {
        "listenPort": 1002,
        "protocol": "tcp",
        "forwardPort": 10002,
        "forwardHost": "fwhost2",
        "accessListenerType": {
          "id": 2,
          "glyph": "glyph2",
          "name": "name2"
        },
        "description": "description-listener-2"
      }
    ],
    "statistics": {
      "isConnectd": null,
      "isOverRestrictiveNetwork": null,
      "lastContact": null,
      "lastContactFromNow": null
    }
  },
  {
    "name": "srv4-fqdn",
    "ipAddress": "1.1.1.4",
    "description": "some description 4",
    "listeners": [
      {
        "listenPort": 1002,
        "protocol": "tcp",
        "forwardPort": 10002,
        "forwardHost": "fwhost2",
        "accessListenerType": {
          "id": 2,
          "glyph": "glyph2",
          "name": "name2"
        },
        "description": "description-listener-2"
      }
    ],
    "statistics": {
      "isConnectd": null,
      "isOverRestrictiveNetwork": null,
      "lastContact": null,
      "lastContactFromNow": null
    }
  },
  {
    "name": "srv5-fqdn",
    "ipAddress": "1.1.1.5",
    "description": "some description 5",
    "listeners": [
      {
        "listenPort": 1002,
        "protocol": "tcp",
        "forwardPort": 10002,
        "forwardHost": "fwhost2",
        "accessListenerType": {
          "id": 2,
          "glyph": "glyph2",
          "name": "name2"
        },
        "description": "description-listener-2"
      }
    ],
    "statistics": {
      "isConnectd": null,
      "isOverRestrictiveNetwork": null,
      "lastContact": null,
      "lastContactFromNow": null
    }
  },
  {
    "name": "srv6-fqdn",
    "ipAddress": "1.1.1.6",
    "description": "some description 6",
    "listeners": null,
    "statistics": {
      "isConnectd": null,
      "isOverRestrictiveNetwork": null,
      "lastContact": null,
      "lastContactFromNow": null
    }
  }
]`
	e := resolveUserAccessToServerDependency(&ua, srvrs)
	outbcurr, _ := json.MarshalIndent(e, "", "  ")
	outcurr := string(outbcurr)
	fmt.Println(outcurr)
	if outexp != outcurr {
		t.Fatalf("resolveUserAccessToServerDependency() returns unexpecxted output. \nExpected: \n%s, \nCurrent: \n%s", outexp, outcurr)
	}
}
