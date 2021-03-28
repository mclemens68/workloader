package dag

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brian1917/illumioapi"
	"github.com/brian1917/workloader/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// APIResponse contains the information from the response of the API
type APIResponse struct {
	RespBody   string
	StatusCode int
	Header     http.Header
	Request    *http.Request
	ReqBody    string
}

// DagRequest contains the information for the API Request
type DagRequest struct {
	XMLName xml.Name `xml:"uid-message"`
	Type    string   `xml:"type"`
	Version string   `xml:"version,omitempty"`
	Payload Payload  `xml:"payload"`
}

// Payload contains the information for the API Request
type Payload struct {
	Register   RegIPs `xml:"register,omitempty"`
	Unregister RegIPs `xml:"unregister,omitempty"`
}

// Register contains the information for the API Request
type RegIPs struct {
	Entry []Entry `xml:"entry,omitempty"`
}

// DagResponse - Declare Response Struct for PAN API call
type DagResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Result  Result   `xml:"result,omitempty"`
	MSG     MSG      `xml:"msg,omitempty"`
}

// MSG - Declare Result container of PAN API call
type MSG struct {
	Line Line `xml:"line,omitempty"`
}

// Line - Declare Entry container of PAN API call
type Line struct {
	UIDResponse UIDResponse `xml:"uid-response,omitempty"`
}

// Line - Declare Entry container of PAN API call
type UIDResponse struct {
	Version string  `xml:"version,omitempty"`
	Payload Payload `xml:"payload,omitempty"`
}

// Result - Declare Result container of PAN API call
type Result struct {
	Entry   []Entry `xml:"entry,omitempty"`
	Count   int     `xml:"count,omitempty"`
	Error   string  `xml:"error,omitempty"`
	Enabled string  `xml:"enabled,omitempty"`
	Group   Group   `xml:"group,omitempty"`
}

// Entry - Declare Entry container of PAN API call
type Entry struct {
	IP         string `xml:"ip,attr"`
	Message    string `xml:"message,attr,omitempty"`
	FromAgent  string `xml:"from_agent,attr,omitempty"`
	Persistent string `xml:"persistent,attr,omitempty"`
	Tag        Tag    `xml:"tag,omitempty"`
}

// Global - Declare Entry container of PAN API call
type Group struct {
	LocalInfo LocalInfo `xml:"local-info,omitempty"`
}

type LocalInfo struct {
	State string `xml:"state,omitempty"`
}

// Tag - Declare Entry container of PAN API call
type Tag struct {
	Members []Member `xml:"member,omitempty"`
}

// Tag - Declare Entry container of PAN API call
type Member struct {
	Member  string `xml:",chardata"`
	Timeout string `xml:"timeout,attr,omitempty"`
}

//PAN structure used to
type PAN struct {
	Key    string
	URL    string
	RegIPs map[string]IPTags
}

//List of New or Updates RegisteredIPs
type IPTags struct {
	Labels []string
	Found  bool
}

// Declare local global variables
var pce illumioapi.PCE
var err error
var noPrompt, addIPv6, update, insecure, clean, removeOld, changePersistent bool
var outFormat, panURL, panKey, panVsys, illumioTag, filterFile, timeout string

func init() {
	DAGSyncCmd.Flags().StringVarP(&panURL, "url", "u", "", "URL required to reach Panorama or PAN FW(requires https://).")
	DAGSyncCmd.Flags().StringVarP(&panKey, "key", "k", "", "Key used to authenticate with Panorama or PAN FW.")
	DAGSyncCmd.Flags().StringVarP(&panVsys, "vsys", "v", "vsys1", "Vsys used to progam registered IPs and tags. Default =\"vsys1\"")
	DAGSyncCmd.Flags().BoolVarP(&addIPv6, "ipv6", "6", false, "Include IPv6 addresses in the syncing of PCE IP and labels/tags with PAN DAGs")
	DAGSyncCmd.Flags().BoolVarP(&insecure, "insecure", "i", false, "Ignore SSL certificate validation when communicating with PAN.")
	DAGSyncCmd.Flags().BoolVarP(&update, "update-panos", "", false, "By default do not Sync Illumio PCE IP address and labels/tags to PAN DAGs but provide output and log what would have synced.")
	DAGSyncCmd.Flags().StringVarP(&filterFile, "file", "f", "", "Enter filename for CSV that has labels to filter on")
	DAGSyncCmd.Flags().StringVarP(&timeout, "timeout", "t", "0", "Enter filename for CSV that has labels to filter on")
	DAGSyncCmd.Flags().BoolVarP(&removeOld, "remove-stale", "r", false, "Remove all Registered IPs that don't have IP on the PCE")
	DAGSyncCmd.Flags().BoolVarP(&changePersistent, "persistent", "p", false, "RegisterIPs are persistent by default.")
	DAGSyncCmd.Flags().BoolVarP(&clean, "clean", "c", false, "Remove all Registered IPs from PAN")
	DAGSyncCmd.Flags().MarkHidden("clean")
	DAGSyncCmd.Flags().StringVarP(&illumioTag, "mark", "", "%#ILLUMIO-ADDED#%", "Ignore adding and looking for ILLLUMIO tag - %#ILLUMIO-ADDED#% ")
	DAGSyncCmd.Flags().MarkHidden("mark")

}

// DAGSyncCmd runs the DAG register/unregister PAN API Sync
var DAGSyncCmd = &cobra.Command{
	Use:   "dagsync",
	Short: "Syncs IPs and Labels for Workloads between PCE and Dynamic Access Group on Palo Alto Devices",
	Long: `
Collects from the workloader default PCE all workload IPs and labels. Workloader will push the IPs and Labels/Tag into a PanOS device's RegisteredIP objects to be used by Dynamic Access Groups.  

To be able to access the PanOS device you must pass the URL, and API Key of the PanOS device.  You can configure environment variables (PANOS_URL and  PANOS_KEY) or enter ("-u" or "--url") for PanOS URL and  ("-k" or "--key") for PanOS API Key.  Workloader also requires a "vsys" value to be sent with each message to the PanOS device.  By default the value will use "vsys1".  To change that to another value use ("-v" or "vsys") or configure the environment variable PANOS_VSYS.  Failure to configure PANOS_URL and/or PANOS_KEY will cause workloader with exit. 

To filter only workloads with certain labels you can include a CSV file via "-f" or "--file. The CSV file must have a header of role,app,env,loc.  Every row after that should have the labels you want to include.  Any row will match all 4 of the labels if present.  If any row has a blank entry any label on a workload for that label type will match." 

Workloader will add an additional tag when adding workload IPs/Labels to the PanOS.  The extra tag is used to help uniquely match PanOS and PCE IPs.  If you dont want to add the label add ("-t" "" or "--tag" "") to the command line.  If you want to change the default tag text enter ("-t" "<UserDefinedTag>" or "--tag" "<UserDefinedTag>").

Workloader will ignore any IPv6 address on any PCE workload and add IPv4 addresses only.  To add IPv6 addresses as well enter "-6" or "--ipv6".  *Note All ipv4 or ipv6 link local addresses will always be ignored (169.254.0.0/16 or FE80::/10).

Workloader can remove stale objects on the PanOS that are not on the PCE anymore.  By default workloader does not do that.  You can remove these objects by entering "-r" or "--remove-stale".

The update-pce flag is ignored for this command.`,
	Run: func(cmd *cobra.Command, args []string) {

		// Get the PCE
		pce, err = utils.GetTargetPCE(true)
		if err != nil {
			utils.LogError(err.Error())
		}

		// Get the viper values
		outFormat = viper.Get("output_format").(string)
		noPrompt = viper.Get("no_prompt").(bool)

		dagSync()
	},
}

// httpSetUp - Used to make API call to PAN.  Require HTTP Action, URL, body (if present), if SSL cert ignored and headers (if present).
func httpSetUp(httpAction, apiURL string, body []byte, disableTLSChecking bool, headers [][2]string) (APIResponse, error) {

	var response APIResponse
	var httpBody *bytes.Buffer

	// Validate the provided action
	httpAction = strings.ToUpper(httpAction)
	if httpAction != "GET" && httpAction != "POST" && httpAction != "PUT" && httpAction != "DELETE" {
		return response, errors.New("invalid http action string. action must be GET, POST, PUT, or DELETE")
	}

	// Create body
	httpBody = bytes.NewBuffer(body)

	// Create HTTP client and request
	client := &http.Client{}
	if disableTLSChecking == true {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest(httpAction, apiURL, httpBody)
	if err != nil {
		return response, err
	}

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
	response.RespBody = string(data[:])
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

//panHTTP - Function to setup HTTP POST with necessary headers and other requirements
func (pan *PAN) callHTTP(cmdType string, cmd string) DagResponse {

	var dagResp DagResponse
	apiURL := fmt.Sprintf("%s/api", pan.URL)
	urlInfo := url.Values{}
	urlInfo.Set("key", pan.Key)
	urlInfo.Set("type", cmdType)
	urlInfo.Set("cmd", cmd)
	urlInfo.Set("vsys", panVsys)

	url, err := url.ParseRequestURI(apiURL)
	if err != nil {
		utils.LogError(fmt.Sprintf("Get Registered IP URL Parse failed - %s", err))
	}

	resp, err := httpSetUp(http.MethodPost, url.String(), []byte(urlInfo.Encode()), insecure, [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}, {"Content-Length", strconv.Itoa(len(urlInfo.Encode()))}})
	if err != nil {
		utils.LogError(fmt.Sprintf("PanHTTP Call failed - %s", err))
	}

	//fmt.Println(urlInfo, resp.RespBody)
	//Unmarshal the HTTP call and place in DagResponse.
	if err := xml.Unmarshal([]byte(resp.RespBody), &dagResp); err != nil {
		utils.LogError(fmt.Sprintf("Unmarshall HTTPSetUp response - %s - Body - %s", err, resp.ReqBody))
	}
	//check to see that the results do not have an error.
	if dagResp.Result.Error != "" {
		utils.LogError(fmt.Sprintf("API request has Error - %s", dagResp.Result.Error))
	}

	return dagResp
}

//ipv6Check - Function that checks IP string for valid IP.  Also checks to see if Ipv6 and if IPv6 should be included
func ipCheck(ip string) string {

	//make sure ip string is a valid IP.
	if net.ParseIP(ip) == nil {
		utils.LogError(fmt.Sprintf("Invalid IP addres from PCE - %s", ip))
	}

	//skip all link local addresses
	_, ipv4LL, _ := net.ParseCIDR("169.254.0.0/16")
	_, ipv6LL, _ := net.ParseCIDR("fe80::/10")

	//Check if the IP is v4 or v6.  For v6 only add if command option enabled.
	if strings.Contains(ip, ".") && !ipv4LL.Contains(net.ParseIP(ip)) {
		return ip
	}
	if strings.Contains(ip, ":") && addIPv6 && !ipv6LL.Contains(net.ParseIP(ip)) {
		return ip
	}

	return ""
}

//workloadIPMap - Build a map of all workloads IPs and their corresponding labels.
func workloadIPMap(filterList []map[string]string) map[string]IPTags {
	var pceIpMap = make(map[string]IPTags)

	wklds, a, err := pce.GetAllWorkloads()
	utils.LogAPIResp("GetAllWorkloads", a)
	if err != nil {
		utils.LogError(fmt.Sprintf("getting all workloads - %s", err))
	}

	for _, w := range wklds {
		var labels []string

		//Make sure there is a Tag to add.
		if len(*w.Labels) == 0 {
			continue
		}

		//matchValue := 0

		//Cycle through labels getting the Value from the HrefLabelMap as well as build a label map to use for filtering
		wkldLabels := make(map[string]string)
		for _, l := range *w.Labels {
			labels = append(labels, pce.Labels[l.Href].Value)
			wkldLabels[pce.Labels[l.Href].Key] = pce.Labels[l.Href].Value
		}

		match := false
		for i := 1; i < len(filterList); i++ {
			numMatch := 0
			for k, v := range filterList[i] {
				if v == "" {
					numMatch++
					continue
				}
				if _, ok := wkldLabels[k]; !ok {
					numMatch++
					continue
				}
				if wkldLabels[k] == v {
					numMatch++
				}
			}
			//found match
			if numMatch == 4 {
				match = true
				break
			}
		}
		if filterFile == "" {
			match = true
		}
		if match {
			for _, ip := range w.Interfaces {
				if ipCheck(ip.Address) != "" {
					pceIpMap[ip.Address] = IPTags{Labels: labels, Found: false}
				}
			}
		}

	}

	return pceIpMap
}

//getPanRegisteredIPs - Get all currently loaded Registered IPs from PAN.  Uses to compare against PCE workload IPs to sync.
func (pan *PAN) LoadRegisteredIPs() {

	var dagResp DagResponse

	//var tmpDagEntries = make(map[string][]string)

	//Send Set VSYS API request.  panHttp check for success within the response message.  Fails if not successful.
	setVsysCMD := fmt.Sprintf("<set><system><setting><target-vsys>%s</target-vsys></setting></system></set>", panVsys)
	dagResp = pan.callHTTP("op", setVsysCMD)

	//remove parameter so we can readd
	entryLimit := 500
	startPoint := 1
	//limit calls to 500.  and Cycle through if you find more.
	getRegIPCMD := "<show><object><registered-ip><all></all></registered-ip></object></show>"

	totalCount := 0
	illumioCount := 0
	for {
		//Send GET Registered IP API request.  panHttp check for success within the response message.  Fails if not successful.
		dagResp = pan.callHTTP("op", getRegIPCMD)

		//Add the discovered registered IPs and Tags to global variable used for syncing.  Make sure ILLUMIOSTR is present in list and remove.
		for _, e := range dagResp.Result.Entry {
			found := false
			if net.ParseIP(e.IP) == nil {
				utils.LogError(fmt.Sprintf("Invalid IP addres from PanOS - %s", e.IP))
				continue
			}

			//Must Create a Member struct for each label.  Needed to add timeout option.
			allLabels := []string{}
			for _, m := range e.Tag.Members {
				allLabels = append(allLabels, m.Member)
			}
			//If we want to Ignore illumio Tags
			if illumioTag != "" {
				if ok, newEntry := pan.FindandRemoveEntry(allLabels, illumioTag); ok {
					//if ok, newEntry := pan.FindandRemoveEntry(e.Tag.Members, illumioTag); ok {
					found = true
					pan.RegIPs[net.ParseIP(e.IP).String()] = IPTags{Found: found, Labels: newEntry}
					//tmpDagEntries[net.ParseIP(e.IP).String()] = newEntry

					illumioCount++
				}
				continue
			}
			//Cover how to count when we dont care about IllumioTag..
			if illumioTag == "" {
				illumioCount++
			}
			pan.RegIPs[net.ParseIP(e.IP).String()] = IPTags{Found: found, Labels: allLabels}
			//tmpDagEntries[net.ParseIP(e.IP).String()] = e.Tag.Members

		}
		totalCount += len(dagResp.Result.Entry)
		//If number of entries less than per call limit no more request to call. Otherwise move start point + entryLimits and request again.
		if dagResp.Result.Count < entryLimit {
			break

		} else {
			startPoint += entryLimit
			getRegIPCMD = fmt.Sprintf("<show><object><registered-ip><limit>%d</limit><start-point>%d</start-point></registered-ip></object></show>", entryLimit, startPoint)
		}

	}
	//print out total and how many RegisterIPs are available to work with. *note using -t "" counts all registerIPs.
	utils.LogInfo(fmt.Sprintf("%d Total RegisteredIPs on PanOS. Of those RegisteredIPs %d previously added by PCE ", totalCount, illumioCount), true)

	//Send Set VSYS back to "none" API request.  panHttp check for success within the response message.  Fails if not successful.
	setVsysCMD = "<set><system><setting><target-vsys>none</target-vsys></setting></system></set>"
	dagResp = pan.callHTTP("op", setVsysCMD)

}

//UnRegister - Call PAN to remove IPs or Labels.
func (pan *PAN) UnRegister(listRegisterIP map[string]IPTags) {
	var request DagRequest
	var entries []Entry

	//If the label list=0 then its is just an IP then it should be removed.  Remove no matter if there are labels if flush is selected.
	for ip, labels := range listRegisterIP {
		if len(labels.Labels) == 0 || clean {
			entries = append(entries, Entry{IP: ip}) //, Tag: Tag{Members: labels}
			utils.LogInfo(fmt.Sprintf("Unregister %s", ip), false)
		} else {

			//Must Create a Member struct for each label.  Needed to add timeout option.
			allMembers := []Member{}
			for _, l := range labels.Labels {
				allMembers = append(allMembers, Member{Member: l, Timeout: timeout})
			}
			entries = append(entries, Entry{IP: ip, Tag: Tag{Members: allMembers}})
			utils.LogInfo(fmt.Sprintf("Unregistering Labels %s - labels %s", ip, labels.Labels), false)
		}
	}
	request = DagRequest{Type: "update", Version: "2.0", Payload: Payload{Unregister: RegIPs{Entry: entries}}}

	//Create and Send API call to PAN to unregister
	xmlData, _ := xml.MarshalIndent(request, "", "")
	dagResp := pan.callHTTP("user-id", string(xmlData))
	if dagResp.Status != "success" {
		utils.LogInfo("UnRegister API response received error. Check logs", true)
		for _, entry := range dagResp.MSG.Line.UIDResponse.Payload.Unregister.Entry {
			utils.LogInfo(fmt.Sprintf("Unregister received error - %s", entry), false)
		}
	}
	utils.LogInfo(fmt.Sprintf("%d IPs and/or Tags were unregistered on PAN", len(listRegisterIP)), true)
}

//Register - Call PAN to add IPs and labels to Registered IPs
func (pan *PAN) Register(listRegisterIP map[string]IPTags) {
	var request DagRequest
	var entries []Entry

	for ip, labels := range listRegisterIP {
		if illumioTag != "" && !labels.Found {
			labels.Labels = append(labels.Labels, illumioTag)
		}
		//Must Create a Member struct for each label.  Needed to add timeout option.
		allMembers := []Member{}
		for _, l := range labels.Labels {
			allMembers = append(allMembers, Member{Member: l, Timeout: timeout})
		}
		p := "1"
		if changePersistent {
			p = "0"
		}
		entries = append(entries, Entry{IP: ip, FromAgent: "0", Persistent: p, Tag: Tag{Members: allMembers}})
		utils.LogInfo(fmt.Sprintf("Register %s with the following labels %s", ip, labels.Labels), false)
	}
	request = DagRequest{Type: "update", Version: "2.0", Payload: Payload{Register: RegIPs{Entry: entries}}}

	//If update set send api to PAN

	xmlData, _ := xml.MarshalIndent(request, "", "")
	dagResp := pan.callHTTP("user-id", string(xmlData))
	if dagResp.Status != "success" {
		utils.LogInfo("Register API response received error. Check logs", true)
		for _, entry := range dagResp.MSG.Line.UIDResponse.Payload.Register.Entry {
			utils.LogInfo(fmt.Sprintf("Register received error - %s", entry), false)
		}

	}

	utils.LogInfo(fmt.Sprintf("%d IPs and/or Tags were updated/registered on PAN", len(listRegisterIP)), true)
}

//checkHAPrimary - make sure we are adding Registered IPs to primary PAN in a HA
func (pan *PAN) checkHA() bool {

	//Send show HA API request.  panHttp check for success within the response message.  Fails if not successful.
	setVsysCMD := "<show><high-availability><state></state></high-availability></show>"
	dagResp := pan.callHTTP("op", setVsysCMD)

	if strings.ToLower(dagResp.Result.Enabled) == "no" {
		return true
	}
	if strings.ToLower(dagResp.Result.Group.LocalInfo.State) == "active" || strings.ToLower(dagResp.Result.Group.LocalInfo.State) == "active-primary" {
		return true
	}
	return false

}

//Remove element in string
func (pan *PAN) removeEntry(slice []string, i int) []string {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

// Contains tells whether a contains x.
func (pan *PAN) FindandRemoveEntry(a []string, x string) (bool, []string) {
	for i, n := range a {
		if x == n {
			return true, pan.removeEntry(a, i)
			//return true, a
		}
	}
	return false, []string{}
}

//isEqual -  compare function for arrays - Order not guaranteed
func isEqual(a1 []string, a2 []string) (bool, []string, []string) {

	var remove []string
	var equal bool = true

	//create a map of all elements in first array
	add := make(map[string]bool)
	for _, item := range a2 {
		add[item] = true
	}

	var addLabels []string
	for _, v := range a1 {
		//if _, ok := add[v]; !ok && v != illumioTag {
		if _, ok := add[v]; !ok {
			equal = false
			remove = append(remove, v)
		} else if ok {
			delete(add, v)
		}
	}
	if len(a1) < len(a2) {
		equal = false
	}

	for k := range add {
		addLabels = append(addLabels, k)
	}
	return equal, remove, addLabels
}

//dagSync - Compares IPs already registered on PAN with those on the PCE also compare the labels/tags currently configured.  If different labels/tags
func dagSync() {

	//Enter Start Log for PAN DAG Sync
	utils.LogStartCommand(fmt.Sprintf("PanOS DAG Sync - change=%t, insecure=%t, ipv6=%t, flush=%t, rmeoveOld=%t", update, insecure, addIPv6, clean, removeOld))

	//Create PAN struct with empty map of registered IPs

	if tmp := os.Getenv("PANOS_URL"); tmp != "" && panURL == "" {
		panURL = tmp
	} else if panURL == "" {
		utils.LogError("User must either use environment variable \"PANOS_URL\" or \"--url\" or \"-u\"")
	}

	if tmp := os.Getenv("PANOS_KEY"); tmp != "" && panKey == "" {
		panKey = tmp
	} else if panKey == "" {
		utils.LogError("User must either use environment variable \"PANOS_KEY\" or \"--key\" or \"-k\"")
	}

	//Too override default --vsys vsys1 check to see the default is selected and environment variable is set.
	if tmp := os.Getenv("PANOS_VSYS"); tmp != "" && panVsys == "vsys1" {
		panVsys = tmp
	} else if panVsys == "" {
		utils.LogError("User must either use environment variable \"PANOS_VSYS\" or \"--url\" or \"-u\"")
	}

	pan := PAN{Key: panKey, URL: panURL, RegIPs: map[string]IPTags{}}

	//Check to see if URL is for non-HA or active/active-primary PAN.  Need to only push IPs to active.
	if !pan.checkHA() {
		utils.LogError(fmt.Sprintf("URL entered is trying to use backup HA device. URL - %s", panURL))
	}

	// Parse the CSV File if there is one.
	fileData := [][]string{}
	var err error
	if filterFile != "" {
		fileData, err = utils.ParseCSV(filterFile)
		if err != nil {
			utils.LogError(err.Error())
		}
	}

	//build filter structure and check for empty row.
	var filter []map[string]string
	//check that row has entries if not tell end user.
	for i, row := range fileData {
		totLen := 0
		for _, c := range row {
			if len(c) != 0 {
				totLen += len(c)
			}
		}
		if totLen == 0 {
			utils.LogInfo(fmt.Sprintf("Filter File Row %d does not has ANY entries..This will cause everything to match", i), true)
		}
		//Build filter structure to be used when getting PCE workloads.
		filter = append(filter, map[string]string{"role": row[0], "app": row[1], "env": row[2], "loc": row[3]})
	}

	//Get PAN registered IPs and Workload IPs from PAN/PCE
	utils.LogInfo(fmt.Sprintf("Calling get Registered-IP on PanOS - %s", panURL), true)
	pan.LoadRegisteredIPs()

	//Get all Workloads from PCE.  Dont do if you are cleanup RegisteredIPs.
	workloadsMap := make(map[string]IPTags)
	if !clean {
		workloadsMap = workloadIPMap(filter)
		utils.LogInfo(fmt.Sprintf("Found %d Workloads on PCE - %s", len(workloadsMap), pce.FQDN), true)
	}

	//clear RegisterIPs and exit.  Make sure user adds --update-panos. Prompt user to make sure they want to do this..
	if clean && len(pan.RegIPs) != 0 {
		if !noPrompt && update {
			var prompt string
			fmt.Printf("\r\n%s [PROMPT] - workloader will flush %d IPs/Tags on the following PanOS: %s. Do you want to continue (yes/no)? ", time.Now().Format("2006-01-02 15:04:05 "), len(pan.RegIPs), panURL)
			fmt.Scanln(&prompt)
			if strings.ToLower(prompt) != "yes" {
				utils.LogInfo(fmt.Sprintf("prompt denied flushing %d entries.", len(pan.RegIPs)), true)
				utils.LogEndCommand("wkld-import")
				return
			}
		}
		if !update {
			utils.LogInfo(fmt.Sprintf("%d unregister changes will NOT be made - must enter \"--update-panos\" to make changes to PAN!!!", len(pan.RegIPs)), true)
			utils.LogEndCommand("dag-sync")
			return
		} else {
			utils.LogInfo(fmt.Sprintf("Flushing %d Register-IPs", len(pan.RegIPs)), true)
			pan.UnRegister(pan.RegIPs)
			utils.LogEndCommand("dag-sync")
			return
		}
	}

	//If there are no entries from PAN to match against just add all the workloads.
	if len(pan.RegIPs) == 0 && len(workloadsMap) != 0 {
		if !noPrompt && update {
			var prompt string
			fmt.Printf("\r\n%s [PROMPT] - workloader will register %d IPs/Tags on the following PanOS : %s. Do you want to make these changes (yes/no)? ", time.Now().Format("2006-01-02 15:04:05 "), len(workloadsMap), panURL)
			fmt.Scanln(&prompt)
			if strings.ToLower(prompt) != "yes" {
				utils.LogInfo(fmt.Sprintf("prompt denied to registered %d IPs/Tags.", len(workloadsMap)), true)
				utils.LogEndCommand("wkld-import")
				return
			}
		}
		if !update {
			utils.LogInfo(fmt.Sprintf("%d register changes will NOT be made - must enter \"--update-panos\" to make changes to PAN!!!", len(workloadsMap)), true)
			utils.LogEndCommand("dag-sync")
			return
		} else {
			pan.Register(workloadsMap)
			utils.LogEndCommand("dag-sync")
			return
		}
	}

	//Cycle through Workload list as long as there are labels/tags continue.  Build arrays of IPs/Tags to Add/Remove.
	regEntries := make(map[string]IPTags)
	unregEntries := make(map[string]IPTags)
	for ip, labels := range workloadsMap {
		if len(labels.Labels) == 0 {
			continue
		}
		//If there isnt an entry for that IP on the PAN add the workload and labels/tags
		if _, ok := pan.RegIPs[ip]; !ok {
			regEntries[ip] = IPTags{Labels: labels.Labels, Found: false}
			continue
		}
		//Check if both label sets are equal.  If not return the labels to add or remove or both
		if ok, removeLabels, addLabels := isEqual(pan.RegIPs[ip].Labels, labels.Labels); !ok {
			//skip adding these entries if list of labels is empty
			if len(addLabels) != 0 {
				regEntries[ip] = IPTags{Labels: addLabels, Found: true}
			}
			if len(removeLabels) != 0 {
				unregEntries[ip] = IPTags{Labels: removeLabels, Found: true}
			}
		}
	}

	//Find all the register-ips that are on the PAN but not the PCE and if you set option to unregister.  Add to unregister list.
	countStaleIPs := 0
	for ip := range pan.RegIPs {
		if _, ok := workloadsMap[ip]; !ok {
			if removeOld {
				unregEntries[ip] = IPTags{}
			} else {
				utils.LogInfo(fmt.Sprintf("RegisterIPs %s is stale.  But will not be removed from PanOS.", ip), false)
			}
			countStaleIPs++
		}
	}

	if countStaleIPs > 0 && !removeOld {
		utils.LogInfo(fmt.Sprintf("PanOS has %d stale RegisterIPs.  To remove please set \"-r\" or \"--remove-stale\"", countStaleIPs), true)
	}

	if len(regEntries) == 0 && len(unregEntries) == 0 {
		utils.LogInfo(fmt.Sprintf("Nothing to do. No Add/Update/Removals needed on PanOS."), true)
		utils.LogEndCommand("dag-sync")
		return
	}

	// If updatePCE is set, but not noPrompt, we will prompt the user.
	if update && !noPrompt {
		var prompt string
		fmt.Printf("\r\n%s [PROMPT] - workloader will register %d and unregister %d IPs and Tags on the following PanOS : %s. Do you want to make these changes (yes/no)? ", time.Now().Format("2006-01-02 15:04:05 "), len(regEntries), len(unregEntries), panURL)
		fmt.Scanln(&prompt)
		if strings.ToLower(prompt) != "yes" {
			utils.LogInfo(fmt.Sprintf("prompt denied to registered %d and unregistered %d IPs/Tags.", len(regEntries), len(unregEntries)), true)
			utils.LogEndCommand("wkld-import")
			return
		}
	}
	if len(regEntries) != 0 {
		pan.Register(regEntries)
	}
	//make sure there is some unregister updates need
	if len(unregEntries) != 0 {
		pan.UnRegister(unregEntries)
	}
	utils.LogEndCommand("dag-sync")
}
