package model

func testData() {
	db := Connection()

	usr1 := Entity{EntityType: ENTITY_USER, UPN: "valda@cloudfield.cz", Name: "USR 1"}
	db.Create(&usr1)
	usr2 := Entity{EntityType: ENTITY_USER, UPN: "usr2@test.cz", Name: "USR 2"}
	db.Create(&usr2)
	srv1 := Entity{EntityType: ENTITY_SERVER, UPN: "srv1@test.cz", Name: "SRV 1"}
	db.Create(&srv1)
	srv2 := Entity{EntityType: ENTITY_SERVER, UPN: "srv2@test.cz", Name: "SRV 2"}
	db.Create(&srv2)

	grp1 := Group{Name: "AllServers"}
	db.Create(&grp1)
	grp2 := Group{Name: "AppServers"}
	db.Create(&grp2)

	fw1 := Fwconfig{Name: "FW 1"}
	db.Create(&fw1)
	fw1out := Fwconfigout{FwconfigID: fw1.ID, Port: "any", Proto: "any", Host: "any"}
	db.Create(&fw1out)
	fw1in1 := Fwconfigin{FwconfigID: fw1.ID, Port: "any", Proto: "icmp", Host: "any"}
	db.Create(&fw1in1)
	fw1in2 := Fwconfigin{FwconfigID: fw1.ID, Port: "22", Proto: "tcp", Host: "group"}
	db.Create(&fw1in2)
	fw1in2g1 := FwconfiginGroup{FwconfiginID: fw1in2.ID, GroupID: grp1.ID}
	db.Create(&fw1in2g1)
	fw1in2g2 := FwconfiginGroup{FwconfiginID: fw1in2.ID, GroupID: grp2.ID}
	db.Create(&fw1in2g2)

	fw2 := Fwconfig{Name: "FW 2"}
	db.Create(&fw2)
	fw2out := Fwconfigout{FwconfigID: fw2.ID, Port: "any", Proto: "any", Host: "any"}
	db.Create(&fw2out)
	fw2in1 := Fwconfigin{FwconfigID: fw2.ID, Port: "any", Proto: "icmp", Host: "any"}
	db.Create(&fw2in1)
	fw2in2 := Fwconfigin{FwconfigID: fw2.ID, Port: "22", Proto: "tcp", Host: "group"}
	db.Create(&fw2in2)
	fw2in2g1 := FwconfiginGroup{FwconfiginID: fw2in2.ID, GroupID: grp1.ID}
	db.Create(&fw2in2g1)
	fw2in3 := Fwconfigin{FwconfigID: fw2.ID, Port: "8080", Proto: "tcp", Host: "group"}
	db.Create(&fw2in3)
	fw2in3g1 := FwconfiginGroup{FwconfiginID: fw2in3.ID, GroupID: grp2.ID}
	db.Create(&fw2in3g1)

	fw3 := Fwconfig{Name: "FW 3"}
	db.Create(&fw3)
	fw3out1 := Fwconfigout{FwconfigID: fw3.ID, Port: "any", Proto: "icmp", Host: "any"}
	db.Create(&fw3out1)
	fw3out2 := Fwconfigout{FwconfigID: fw3.ID, Port: "any", Proto: "tcp", Host: "group"}
	db.Create(&fw3out2)
	fw3out1g1 := FwconfigoutGroup{FwconfigoutID: fw3out2.ID, GroupID: grp1.ID}
	db.Create(&fw3out1g1)
	fw3in1 := Fwconfigin{FwconfigID: fw3.ID, Port: "any", Proto: "icmp", Host: "any"}
	db.Create(&fw3in1)

	usr1a1 := Access{Name: "usr1 access 1", IpAddress: "192.168.241.1", EntityID: usr1.ID, FwconfigID: fw3.ID}
	db.Create(&usr1a1)
	usr1a1c := Certificate{AccessID: usr1a1.ID, Fingerprint: "xxx"}
	db.Create(&usr1a1c)

	usr1a2 := Access{Name: "usr1 access 2", IpAddress: "192.168.241.101", EntityID: usr1.ID, FwconfigID: fw3.ID}
	db.Create(&usr1a2)
	usr1a2c := Certificate{AccessID: usr1a2.ID, Fingerprint: "xxx"}
	db.Create(&usr1a2c)

	usr2a1 := Access{Name: "usr2 access 1", IpAddress: "192.168.241.2", EntityID: usr2.ID, FwconfigID: fw3.ID}
	db.Create(&usr2a1)
	usr2a1c := Certificate{AccessID: usr2a1.ID, Fingerprint: "xxx"}
	db.Create(&usr2a1c)

	srv1a := Access{Name: "srv1 access 1", IpAddress: "192.168.240.101", EntityID: srv1.ID, FwconfigID: fw1.ID}
	db.Create(&srv1a)
	srv1a1c := Certificate{AccessID: srv1a.ID, Fingerprint: "xxx"}
	db.Create(&srv1a1c)

	srv2a := Access{Name: "srv2 access 1", IpAddress: "192.168.240.102", EntityID: srv2.ID, FwconfigID: fw2.ID}
	db.Create(&srv2a)
	srv2a1c := Certificate{AccessID: srv2a.ID, Fingerprint: "xxx"}
	db.Create(&srv2a1c)

	usr1a1_ag1 := AccessGroup{AccessID: usr1a1.ID, GroupID: grp1.ID}
	db.Create(&usr1a1_ag1)
	usr1a2_ag1 := AccessGroup{AccessID: usr1a2.ID, GroupID: grp1.ID}
	db.Create(&usr1a2_ag1)
	usr1a2_ag2 := AccessGroup{AccessID: usr1a2.ID, GroupID: grp2.ID}
	db.Create(&usr1a2_ag2)
	usr2a1_ag1 := AccessGroup{AccessID: usr2a1.ID, GroupID: grp1.ID}
	db.Create(&usr2a1_ag1)
}
