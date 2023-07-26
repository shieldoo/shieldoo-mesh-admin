package aadimport

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type ADGroups struct {
	Id             string
	Name           string
	NormalizedName string
	Users          []ADUsers
}

type ADUsers struct {
	Id      string
	Upn     string
	Name    string
	IsAdmin bool
}

func LoadGroupsAndUsers(client *msgraphsdk.GraphServiceClient, adminGroupId string, firewallGroups []string) ([]ADGroups, []ADUsers, error) {
	groups, err := allGroups(client)
	var users []ADUsers
	if err != nil {
		return groups, users, err
	}
	adminUsers, err := allGroupMemberUsers(client, adminGroupId)
	if err != nil {
		return groups, users, fmt.Errorf("Failed to load admin users (probably you entered wrong Group Object Id): %w", err)
	}
	//clean up fwGroups
	m := make(map[string]bool)
	for _, g := range groups {
		m[g.Id] = true
	}
	var cleanFwGroups []string
	for _, g := range firewallGroups {
		if _, ok := m[g]; ok {
			cleanFwGroups = append(cleanFwGroups, g)
		}
	}
	err = enrichGroupsForMembers(client, cleanFwGroups, &groups)
	if err != nil {
		return groups, users, err
	}
	users = extractUsersFromGroups(adminUsers, groups)
	return groups, users, nil
}

func CreateGraphClient(tenantId string, clientId string, secret string) (*msgraphsdk.GraphServiceClient, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, secret, nil)
	if err != nil {
		return nil, err
	}

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{})
	if err != nil {
		return nil, err
	}
	return graphClient, nil
}

func normalizeGroupName(s string) string {
	// Define a regular expression to match all characters except letters, numbers, and underscores
	reg := regexp.MustCompile("[^a-zA-Z0-9_]")
	// Replace all non-matching characters with underscores
	s = reg.ReplaceAllString(s, "_")
	return s
}

func extractUsersFromGroups(adminUsers []ADUsers, groups []ADGroups) []ADUsers {
	// extract only unique users
	m := make(map[string]ADUsers)
	var users []ADUsers
	for _, group := range groups {
		for _, user := range group.Users {
			m[user.Id] = user
		}
	}
	for _, user := range adminUsers {
		user.IsAdmin = true
		m[user.Id] = user
	}
	for _, user := range m {
		users = append(users, user)
	}
	return users
}

func allGroups(graphClient *msgraphsdk.GraphServiceClient) ([]ADGroups, error) {
	var groups []ADGroups
	result, err := graphClient.Groups().Get(context.Background(), nil)
	if err != nil {
		return groups, err
	}
	pageIterator, err := msgraphcore.NewPageIterator(result, graphClient.GetAdapter(), models.CreateGroupCollectionResponseFromDiscriminatorValue)
	err = pageIterator.Iterate(context.Background(), func(pageItem interface{}) bool {
		group := pageItem.(*models.Group)
		groups = append(groups, ADGroups{
			Id:             *group.GetId(),
			Name:           *group.GetDisplayName(),
			NormalizedName: normalizeGroupName(*group.GetDisplayName()),
		})
		// Return true to continue the iteration
		return true
	})
	return groups, err
}

func enrichGroupsForMembers(graphClient *msgraphsdk.GraphServiceClient, groupsInFw []string, groups *[]ADGroups) error {
	for _, groupId := range groupsInFw {
		users, err := allGroupMemberUsers(graphClient, groupId)
		if err != nil {
			return err
		}
		for i, _ := range *groups {
			if (*groups)[i].Id == groupId {
				(*groups)[i].Users = users
				break
			}
		}
	}
	return nil
}

func replaceLast(x, y, z string) (x2 string) {
	i := strings.LastIndex(x, y)
	if i == -1 {
		return x
	}
	return x[:i] + z + x[i+len(y):]
}

func allGroupMemberUsers(graphClient *msgraphsdk.GraphServiceClient, id string) ([]ADUsers, error) {
	var users []ADUsers
	result, err := graphClient.GroupsById(id).TransitiveMembers().Get(context.Background(), nil)
	if err != nil {
		return users, err
	}
	pageIterator, err := msgraphcore.NewPageIterator(result, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	err = pageIterator.Iterate(context.Background(), func(pageItem interface{}) bool {
		switch pageItem.(type) {
		case *models.User:
			member := pageItem.(*models.User)
			upn := *member.GetUserPrincipalName()
			displayName := *member.GetDisplayName()
			// exception for external users - ugly but works
			if strings.Contains(upn, "#EXT#") {
				if member.GetMail() == nil {
					uparts := strings.Split(upn, "#EXT#")
					upn = strings.Replace(uparts[0], "#EXT#", "", -1)
					upn = replaceLast(upn, "_", "@")
				} else {
					upn = *member.GetMail()
				}
				displayName += " #EXT#"
			}
			users = append(users, ADUsers{
				Id:   *member.GetId(),
				Upn:  upn,
				Name: displayName,
			})
		}
		// Return true to continue the iteration
		return true
	})
	return users, err
}
