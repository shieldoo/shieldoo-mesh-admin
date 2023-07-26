package graph

import (
	"strconv"
	"strings"
	"time"

	gqlmodel "github.com/shieldoo/shieldoo-mesh-admin/graph/model"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
)

type filteredFWRules struct {
	portFrom int
	portTo   int
	protocol string
}

func filterFWRulesCheckGroups(userGroups []*gqlmodel.Group, grps []model.FwconfiginGroup) bool {
	for _, v := range userGroups {
		for _, w := range grps {
			if v.Name == w.Group.Name {
				return true
			}
		}
	}
	return false
}

func filterFWRulesForUser(userGroups []*gqlmodel.Group, fwrules []model.Fwconfigin) []filteredFWRules {
	var ret []filteredFWRules
	for _, v := range fwrules {
		if v.Proto == "any" || v.Proto == "udp" || v.Proto == "tcp" {
			if v.Host == "any" || (v.Host == "group" && filterFWRulesCheckGroups(userGroups, v.FwconfigGroups)) {
				portF := 0
				portT := 0
				if v.Port == "any" {
					portT = 65535
				} else {
					if strings.Contains(v.Port, "-") {
						s := strings.Split(v.Port, "-")
						if len(s) > 1 {
							i0, err0 := strconv.Atoi(s[0])
							i1, err1 := strconv.Atoi(s[1])
							if err0 == nil && err1 == nil {
								portT = i1
								portF = i0
							}

						}
					} else {
						i, err := strconv.Atoi(v.Port)
						if err == nil {
							portT = i
							portF = i
						}
					}
				}
				ret = append(ret, filteredFWRules{
					portFrom: portF,
					portTo:   portT,
					protocol: v.Proto,
				})
			}
		}
	}
	return ret
}

func filteredFWRulesCheckListener(port int, protocol string, rules []filteredFWRules) bool {
	for _, v := range rules {
		if (v.protocol == "any" || v.protocol == protocol) && port >= v.portFrom && port <= v.portTo {
			return true
		}
	}
	return false
}

func resolveUserAccessToServerDependency(mea *gqlmodel.UserAccess, servers []model.Entity) []*gqlmodel.ServerForAccess {
	var ret []*gqlmodel.ServerForAccess
	for _, v := range servers {
		if len(v.Accesses) > 0 {
			if v.Accesses[0].ValidTo.Before(time.Now()) {
				continue
			}
			r := filterFWRulesForUser(mea.Groups, v.Accesses[0].Fwconfig.Fwconfigins)
			if len(r) == 0 {
				continue
			}
			desc := v.Description
			var lastContact *string
			var lastContactFromNow *int
			if v.Accesses[0].AccessStatistic.Contacted.Year() > 1 {
				tconv := convertDateJson(v.Accesses[0].AccessStatistic.Contacted)
				lastContact = &tconv
				now := time.Now().UTC()
				iconv := int(now.Sub(v.Accesses[0].AccessStatistic.Contacted.UTC()).Seconds())
				lastContactFromNow = &iconv
			}
			s := gqlmodel.ServerForAccess{
				Name:        v.Name,
				IPAddress:   v.Accesses[0].IpAddress,
				Description: &desc,
				Statistics: &gqlmodel.AccessStatistic{
					IsConnectd:               v.Accesses[0].AccessStatistic.IsConnected,
					IsOverRestrictiveNetwork: v.Accesses[0].AccessStatistic.NebulaRestrictiveNetwork,
					LastContact:              lastContact,
					LastContactFromNow:       lastContactFromNow,
				},
			}
			for i, _ := range v.Accesses[0].AccessListeners {
				l := v.Accesses[0].AccessListeners[i]
				if filteredFWRulesCheckListener(l.ListenPort, l.Protocol, r) {
					s.Listeners = append(s.Listeners, &gqlmodel.AccessListener{
						ListenPort:  &l.ListenPort,
						Protocol:    &l.Protocol,
						ForwardPort: &l.ForwardPort,
						ForwardHost: &l.ForwardHost,
						Description: &l.Description,
						AccessListenerType: &gqlmodel.AccessListenerType{
							ID:    l.AccessListenerType.ID,
							Glyph: l.AccessListenerType.Glyph,
							Name:  l.AccessListenerType.Name,
						},
					})
				}
			}
			ret = append(ret, &s)
		}
	}
	return ret
}
