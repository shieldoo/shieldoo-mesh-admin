package model

import (
	"reflect"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-admin/logstore"
)

func LogStoreDatachange(logtype string, upn string, currobj interface{}, oldobj interface{}) {
	// security log
	var entity, isEntity = currobj.(*Entity)
	if isEntity {
		entity.Secret = "*****"
	}
	var access, isAccess = currobj.(*Access)
	if isAccess {
		access.Secret = "*****"
	}
	var useraccess, isUserAccess = currobj.(*UserAccess)
	if isUserAccess {
		useraccess.Secret = "*****"
	}
	lgx := logstore.SecurityLogEntry{
		LogType:        logtype,
		UPN:            upn,
		Timestamp:      time.Now().UTC(),
		Message:        logtype + " " + getType(currobj),
		Entity:         strings.Replace(getType(currobj), "*", "", -1),
		CurrentObject:  currobj,
		OriginalObject: oldobj,
	}
	lgx.Store()
}

func getType(myvar interface{}) string {
	if t := reflect.TypeOf(myvar); t.Kind() == reflect.Ptr {
		return "*" + t.Elem().Name()
	} else {
		return t.Name()
	}
}
