package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/pkg/errors"
)

// AzureSession checks if running latest workloader version
type AzureSession struct {
	SubscriptionID string
	Authorizer     autorest.Authorizer
}

func readJSON(path string) (*map[string]interface{}, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, errors.Wrap(err, "Can't open the file")
	}

	contents := make(map[string]interface{})
	err = json.Unmarshal(data, &contents)

	if err != nil {
		err = errors.Wrap(err, "Can't unmarshal file")
	}

	return &contents, err
}

func newSessionFromFile() (*AzureSession, error) {

	authorizer, err := auth.NewAuthorizerFromFile(azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "Can't initialize authorizer")
	}

	authInfo, err := readJSON(os.Getenv("AZURE_AUTH_LOCATION"))

	if err != nil {
		return nil, errors.Wrap(err, "Can't get authinfo")
	}

	sess := AzureSession{
		SubscriptionID: (*authInfo)["subscriptionId"].(string),
		Authorizer:     authorizer,
	}

	return &sess, nil
}

func getGroups(sess *AzureSession) ([]string, error) {
	tab := make([]string, 0)
	var err error

	grClient := resources.NewGroupsClient(sess.SubscriptionID)
	grClient.Authorizer = sess.Authorizer

	for list, err := grClient.ListComplete(context.Background(), "", nil); list.NotDone(); err = list.Next() {
		if err != nil {
			return nil, errors.Wrap(err, "error traverising RG list")
		}
		rgName := *list.Value().Name
		tab = append(tab, rgName)
	}
	return tab, err
}

func getVM(sess *AzureSession, rg string, keyMap map[string]string) map[string]cloudData {

	vmClient := compute.NewVirtualMachinesClient(sess.SubscriptionID)
	vmClient.Authorizer = sess.Authorizer

	allVMs := make(map[string]cloudData)
	for vm, err := vmClient.ListComplete(context.Background(), rg); vm.NotDone(); err = vm.Next() {
		if err != nil {
			log.Print("got error while traverising RG list: ", err)
		}

		i := vm.Value()
		vmdata := cloudData{Location: *i.Location, Name: *i.Name, OsType: i.VirtualMachineProperties.StorageProfile.OsDisk.OsType, Tags: make(map[string]string), VMID: *i.VirtualMachineProperties.VMID}
		if azureRegion != "" && azureRegion != *i.Location {
			continue
		} else {
			state := ""
			if vmView, err := vmClient.InstanceView(context.Background(), rg, *i.Name); err == nil {
				for _, status := range *vmView.Statuses {
					code := strings.Split(*status.Code, "/")
					switch code[0] {
					case "PowerState":
						state = code[1]
					}
				}
				vmdata.State = state
			} else {
				log.Print("got error while pulling powerstate InstanceView data: ", err)
			}

			vmdata := cloudData{State: state, Location: *i.Location, Name: *i.Name, OsType: i.VirtualMachineProperties.StorageProfile.OsDisk.OsType, Tags: make(map[string]string), VMID: *i.VirtualMachineProperties.VMID}

			//fill out the struct Tag field where RAEL will live
			for k, v := range i.Tags {
				if keyMap[k] != "" {
					vmdata.Tags[keyMap[k]] = *v
				}

			}
			for _, networkInt := range *i.VirtualMachineProperties.NetworkProfile.NetworkInterfaces {
				tmpnetintid := strings.Split(*networkInt.ID, "/")[len(strings.Split(*networkInt.ID, "/"))-1]
				vmNetwork := network.NewInterfacesClient(sess.SubscriptionID)
				vmNetwork.Authorizer = sess.Authorizer

				results, err := vmNetwork.Get(context.Background(), rg, tmpnetintid, "")
				if err != nil {
					log.Print("got error while getting network profile: ", err)
				}

				for _, ipconfig := range *results.InterfacePropertiesFormat.IPConfigurations {
					var tmpIP Interface
					tmpIP.PrivateName = tmpnetintid
					tmpIP.PrivateIP = append(tmpIP.PrivateIP, *ipconfig.InterfaceIPConfigurationPropertiesFormat.PrivateIPAddress)
					tmpIP.Primary = *ipconfig.InterfaceIPConfigurationPropertiesFormat.Primary
					if ipconfig.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress != nil {
						tmppubid := strings.Split(*ipconfig.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID, "/")[len(strings.Split(*ipconfig.InterfaceIPConfigurationPropertiesFormat.PublicIPAddress.ID, "/"))-1]

						vmPublicNet := network.NewPublicIPAddressesClient(sess.SubscriptionID)
						vmPublicNet.Authorizer = sess.Authorizer
						results, err := vmPublicNet.Get(context.Background(), rg, tmppubid, "")
						if err != nil {
							log.Print("got error while getting network profile: ", err)
						}
						if results.PublicIPAddressPropertiesFormat.IPAddress != nil {
							tmpIP.PublicIP = *results.PublicIPAddressPropertiesFormat.IPAddress
							tmpIP.PublicName = tmppubid

						}
					}
					vmdata.Interfaces = append(vmdata.Interfaces, tmpIP)
				}
			}
		}
		allVMs[*i.VirtualMachineProperties.VMID] = vmdata
	}
	return allVMs
}

func addmap(a map[string]cloudData, b map[string]cloudData) map[string]cloudData {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func azureHTTP(keyMap map[string]string) map[string]cloudData {

	sess, err := newSessionFromFile()

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	groups, err := getGroups(sess)

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	allVMs := make(map[string]cloudData)
	for _, group := range groups {
		if group == azureRG || azureRG == "" {
			allVMs = addmap(allVMs, getVM(sess, group, keyMap))
		}
	}
	return allVMs
}
