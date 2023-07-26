package graph

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
	"github.com/shieldoo/shieldoo-mesh-admin/model"
	"github.com/shieldoo/shieldoo-mesh-admin/myjwt"
	"github.com/shieldoo/shieldoo-mesh-admin/utils"
)

var _cfg *utils.Config

func Init(cfg *utils.Config) {
	_cfg = cfg
}

func getPreloads(ctx context.Context) []string {
	return getNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"",
	)
}
func getNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string) (preloads []string) {
	for _, column := range fields {
		prefixColumn := getPreloadString(prefix, column.Name)
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads, getNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn)...)
	}
	return
}
func getPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}
	return name
}
func contains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func logstoreInsertOrUpdate(x interface{}) string {
	if x == nil {
		return logstore.LOGTYPE_DATAINSERT
	} else {
		return logstore.LOGTYPE_DATAUPDATE
	}
}

func checkAdminOrUserAccess(ctx context.Context, UserAccessId int) error {
	accerr := myjwt.JwtRoleCheckerContextADMINISTRATOR(ctx)
	if accerr == nil {
		return nil
	}
	if uaccerr := myjwt.JwtRoleCheckerContextUSER(ctx); uaccerr != nil {
		return uaccerr
	}
	//check if UPN of USER in record is same as UPN of USER in context
	upn := myjwt.ClaimUserNameFromContext(ctx)
	return model.DacCheckUpnForUserAccess(upn, UserAccessId)
}

func checkAdminOrAccess(ctx context.Context, AccessId int) error {
	accerr := myjwt.JwtRoleCheckerContextADMINISTRATOR(ctx)
	if accerr == nil {
		return nil
	}
	if uaccerr := myjwt.JwtRoleCheckerContextUSER(ctx); uaccerr != nil {
		return uaccerr
	}
	//check if UPN of USER in record is same as UPN of USER in context
	upn := myjwt.ClaimUserNameFromContext(ctx)
	return model.DacCheckUpnForAccess(upn, AccessId)
}
