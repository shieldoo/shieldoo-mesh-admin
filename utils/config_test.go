package utils

import (
	"fmt"
	"os"
	"testing"
)

// TestReadConfig calls utils.ReadConfig and checking config struct data
func TestReadConfig(t *testing.T) {
	cfg_Server_Port := "9001"
	os.Setenv("SERVER_PORT", cfg_Server_Port)
	cfg_Auth_Shieldoo_TenantId := "TEST-TENANT"
	os.Setenv("AUTH_SHIELDOO_TENANTID", cfg_Auth_Shieldoo_TenantId)
	cfg_Lighthouses_InstanceMap := "1.2.3.4:6789"
	cfg_Lighthouses_Instances := fmt.Sprintf("%+v", []ConfigLighthouse{
		{Port: 6789, Address: "1.2.3.4"},
	})
	os.Setenv("LIGHTHOUSES_INSTANCESMAP", cfg_Lighthouses_InstanceMap)
	cfg := Init()
	if cfg.Server.Port != cfg_Server_Port {
		t.Fatalf(`utils.ReadConfig() set cfg.ServerPort to wrong value, expected %s, current value %s`, cfg_Server_Port, cfg.Server.Port)
	}
	if cfg.Auth.Shieldoo.TenantId != cfg_Auth_Shieldoo_TenantId {
		t.Fatalf(`utils.ReadConfig() set cfg.Auth.Shieldoo.TenantId to wrong value, expected %s, current value %s`, cfg_Auth_Shieldoo_TenantId, cfg.Auth.Shieldoo.TenantId)
	}
	_tmp_instances := fmt.Sprintf("%+v", cfg.Lighthouses.Instances)
	if _tmp_instances != cfg_Lighthouses_Instances {
		t.Fatalf(`utils.ReadConfig() set cfg.Lighthouses.Instances to wrong value, expected %s, current value %s`, cfg_Lighthouses_Instances, _tmp_instances)
	}
}
