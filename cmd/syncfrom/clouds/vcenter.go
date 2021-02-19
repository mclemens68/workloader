package clouds

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/brian1917/workloader/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// apiResponse contains the information from the response of the API
type apiResponse struct {
	RespBody   string
	StatusCode int
	Header     http.Header
	Request    *http.Request
	ReqBody    string
}

// VCenterSyncCmd checks if the keyfilename is entered.
var VCenterSyncCmd = &cobra.Command{
	Use:   "vcenter",
	Short: "Integrate Azure VMs into PCE.",
	Run: func(cmd *cobra.Command, args []string) {

		pce, err = utils.GetTargetPCE(true)
		if err != nil {
			utils.LogError(fmt.Sprintf("Error getting PCE - %s", err.Error()))
		}
		// Set the CSV file
		if len(args) != 1 {
			fmt.Println("Command requires 1 argument for the csv file. See usage help.")
			os.Exit(0)
		}
		csvFile = args[0]

		// Get the debug value from viper
		debug = viper.Get("debug").(bool)
		updatePCE = viper.Get("update_pce").(bool)
		noPrompt = viper.Get("no_prompt").(bool)

		utils.LogStartCommand("vcenter-sync")

		//load keymapfile, pull data from Azure, use that data to import into PCE.
		keyMap := readKeyFile(csvFile)
		callWkldImport("vcenter", vcenterHTTP(keyMap))
	},
}

func getVMs(filters string) (apiResponse, error) {

	response, err := httpSetUp("GET", "https://sje014-vcenter.illumio.com/rest/com/vmware/cis/session", []byte{}, [][2]string{{}})

	return response, err
}

func httpSetUp(httpAction, apiURL string, body []byte, headers [][2]string) (apiResponse, error) {

	var response apiResponse
	var httpBody *bytes.Buffer
	//var asyncResults asyncResults

	// Validate the provided action
	httpAction = strings.ToUpper(httpAction)
	if httpAction != "GET" && httpAction != "POST" && httpAction != "PUT" && httpAction != "DELETE" {
		return response, errors.New("invalid http action string. action must be GET, POST, PUT, or DELETE")
	}

	// Get the base URL
	//	u, err := url.Parse(apiURL)

	// Create body
	httpBody = bytes.NewBuffer(body)

	// Create HTTP client and request
	client := &http.Client{}
	if pce.DisableTLSChecking == true {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest(httpAction, apiURL, httpBody)
	if err != nil {
		return response, err
	}

	// Set basic authentication and headers
	req.SetBasicAuth(pce.User, pce.Key)

	// Set the user provided headers
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}

	// Make HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return response, err
	}

	// Process response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return response, err
	}

	// Put relevant response info into struct
	response.RespBody = string(data)
	response.StatusCode = resp.StatusCode
	response.Header = resp.Header
	response.Request = resp.Request

	// Check for a 200 response code
	if strconv.Itoa(resp.StatusCode)[0:1] != "2" {
		return response, errors.New("http status code of " + strconv.Itoa(response.StatusCode))
	}

	// Return data and nil error
	return response, nil
}

func vcenterHTTP(keyMap map[string]string) map[string]cloudData {

	utils.LogInfo("VCenter API Session setup - ", false)

	if userID == "" || secret == "" {
		utils.LogError(fmt.Sprintf("Both user - %s", err))
	}

	//Call the EC2 API to get the instance info

	result, err := getVMs("")
	if err != nil {
		utils.LogError(fmt.Sprintf("DescribeInstances error - %s", err))
	}
	utils.LogInfo("AWS DescribeInstance API call - ", false)
	fmt.Println(result)
	//Cycle through all the reservations for all arrays in that reservation
	allVMs := make(map[string]cloudData)
	// for _, res := range result.Reservations {
	// 	for _, instance := range res.Instances {

	// 		if !ignoreState && *instance.State.Name != "running" {
	// 			continue
	// 		}

	// 		// Get all the tags for the instance and compare against keymap values to see if there is a match of PCE RAEL labeks
	// 		var tmpName string
	// 		tmptag := make(map[string]string)
	// 		for _, tag := range instance.Tags {
	// 			if *tag.Key == "Name" {
	// 				tmpName = *tag.Value
	// 			}
	// 			if keyMap[*tag.Key] != "" {
	// 				tmptag[keyMap[*tag.Key]] = *tag.Value
	// 			}
	// 		}
	// 		tmpInstance := cloudData{Name: tmpName, VMID: *instance.InstanceId, Tags: tmptag, Location: region, OsType: "", State: *instance.State.Name}

	// 		//Capture all the instances interfaces and get all IPs for those interfaces.
	// 		for _, intf := range instance.NetworkInterfaces {
	// 			var tmpawsintf netInterface
	// 			if intf.Association != nil && !ignorePublic {
	// 				tmpawsintf.PublicIP = *intf.Association.PublicIp
	// 				tmpawsintf.PublicDNS = *intf.Association.PublicDnsName
	// 			}
	// 			if intf.PrivateDnsName != nil {
	// 				tmpawsintf.PrivateDNS = *intf.PrivateDnsName
	// 			}
	// 			for _, privip := range intf.PrivateIpAddresses {
	// 				tmpawsintf.PrivateIP = append(tmpawsintf.PrivateIP, *privip.PrivateIpAddress)
	// 			}
	// 			tmpInstance.Interfaces = append(tmpInstance.Interfaces, tmpawsintf)

	// 		}
	// 		allVMs[*instance.InstanceId] = tmpInstance

	// 	}

	// }
	utils.LogInfo(fmt.Sprintf("Total EC2 instances discovered - %d", len(allVMs)), true)
	return allVMs

}
