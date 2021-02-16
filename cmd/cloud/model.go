package cloud

import "github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"

// Interface -
type Interface struct {
	PrivateName string
	PrivateIP   []string
	PublicName  string
	PublicIP    string
	Primary     bool
	PublicDNS   string
	PrivateDNS  string
}

type cloudData struct {
	Name       string
	VMID       string
	Tags       map[string]string
	Location   string
	OsType     compute.OperatingSystemTypes
	Interfaces []Interface
	State      string
	
}
