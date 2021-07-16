package wkldpolicy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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

var debug, updatePCE, noPrompt, doNotProvision, console bool
var csvFile, fromPCE, wkldname, outputFileName string
var pce illumioapi.PCE
var err error

func init() {
	WorkloadPolciyExport.Flags().StringVarP(&wkldname, "name", "n", "", "Name of the workload you want exported policy from. Required")
	WorkloadPolciyExport.MarkFlagRequired("namne")
	WorkloadPolciyExport.Flags().BoolVarP(&console, "console", "c", false, "Print data to screen.")

}

// WorkloadToIPLCmd runs the upload command
var WorkloadPolciyExport = &cobra.Command{
	Use:   "wkld-policy [csv file]",
	Short: "Create File containing specific workloads policy.",
	Long: `
	Create File containing specific workloads policy.
`,

	Run: func(cmd *cobra.Command, args []string) {

		// Set the CSV file
		if len(args) != 1 {
			fmt.Println("Command requires 1 argument for the csv file. See usage help.")
			os.Exit(0)
		}
		csvFile = args[0]

		pce, err = utils.GetTargetPCE(true)
		if err != nil {
			utils.LogError(err.Error())
		}

		// Get the debug value from viper
		debug = viper.Get("debug").(bool)
		updatePCE = viper.Get("update_pce").(bool)
		noPrompt = viper.Get("no_prompt").(bool)

		// Disable stdout
		viper.Set("output_format", "csv")
		if err := viper.WriteConfig(); err != nil {
			utils.LogError(err.Error())
		}

		wkldpolicyexport()
	},
}

type WorkloadRules struct {
	WorkloadInstructions []struct {
		ID              string `json:"id"`
		Visibility      string `json:"visibility"`
		EnforcementMode string `json:"enforcement_mode"`
		NetworkAccess   struct {
			Sb struct {
				Ingress []struct {
					PeerSets []string `json:"peer_sets"`
					Pp       []struct {
						Proto int      `json:"proto"`
						Port  []string `json:"port"`
					} `json:"pp"`
					Stateless bool `json:"stateless,omitempty"`
					SecType   int  `json:"sec_type,omitempty"`
					Scp       int  `json:"scp,omitempty"`
				} `json:"ingress"`
				Egress []struct {
					PeerSets []string `json:"peer_sets"`
					Pp       []struct {
						Proto int      `json:"proto"`
						Port  []string `json:"port"`
					} `json:"pp"`
					Stateless bool `json:"stateless,omitempty"`
					TrackFlow bool `json:"track_flow,omitempty"`
				} `json:"egress"`
			} `json:"sb"`
			Ipp struct {
				Ingress []interface{} `json:"ingress"`
				Egress  []struct {
					Proto int           `json:"proto"`
					Type  string        `json:"type"`
					Net   string        `json:"net"`
					ID    string        `json:"id"`
					Pip   []interface{} `json:"pip"`
				} `json:"egress"`
			} `json:"ipp"`
			Forward struct {
				Ingress []interface{} `json:"ingress"`
				Egress  []interface{} `json:"egress"`
			} `json:"forward"`
			Custom []interface{} `json:"custom"`
		} `json:"network_access"`
		SecureConnect struct {
			Profiles []struct {
				ID     int         `json:"id"`
				EspEnc interface{} `json:"esp_enc"`
			} `json:"profiles"`
			IkeAuthenticationType string `json:"ike_authentication_type"`
		} `json:"secure_connect"`
		FirewallOptions []string `json:"firewall_options"`
		NetworkMapping  []struct {
			Net     string   `json:"net"`
			Ifnames []string `json:"ifnames"`
		} `json:"network_mapping"`
		VenOptimizationLevel        string `json:"ven_optimization_level"`
		SecurityPolicyRefreshAction string `json:"security_policy_refresh_action"`
		ContainersInheritHostPolicy bool   `json:"containers_inherit_host_policy"`
		BlockedConnectionAction     string `json:"blocked_connection_action"`
		Ver                         string `json:"ver"`
	} `json:"workload_instructions"`
	Sets struct {
		Networks []struct {
			Net  interface{} `json:"net"`
			Type string      `json:"type"`
			Sets []struct {
				ID    string        `json:"id"`
				Cids  []string      `json:"cids"`
				Ips   []string      `json:"ips"`
				Names []string      `json:"names"`
				Sids  []interface{} `json:"sids"`
			} `json:"sets"`
		} `json:"networks"`
	} `json:"sets"`
}

func httpSetUp(httpAction, apiURL string, pce illumioapi.PCE, body []byte, async bool, headers [][2]string) (illumioapi.APIResponse, error) {

	var response illumioapi.APIResponse
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
	if pce.DisableTLSChecking {
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

	// Set headers for async
	if async {
		req.Header.Set("Prefer", "respond-async")
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

// apicall uses the httpSetup function with the header ContentType set to application/json header
// httpAction must be GET, POST, PUT, or DELETE.
// apiURL is the full endpoint being called.
// PUT and POST methods should have a body that is JSON run through the json.marshal function so it's a []byte.
// async parameter should be set to true for any GET requests returning > 500 items.
func apicall(httpAction, apiURL string, pce illumioapi.PCE, body []byte, async bool) (illumioapi.APIResponse, error) {
	a, e := httpSetUp(httpAction, apiURL, pce, body, async, [][2]string{{"Content-Type", "application/json"}})
	retry := 0

	for a.StatusCode == 429 {
		// If we have already tried 3 times, exit
		if retry > 2 {
			return a, fmt.Errorf("received three 429 errors with 30 second pauses between attempts")
		}
		// Increment the retry counter
		retry++
		// Sleep for 30 seconds
		time.Sleep(30 * time.Second)
		// Retry the API call
		a, e = httpSetUp(httpAction, apiURL, pce, body, async, [][2]string{{"Content-Type", "application/json"}})
	}

	// Return once response code isn't 429 or if we've exceeded our attempts.
	return a, e
}

// GetWkdlRules returns an slice of workloads in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func GetWorkloadRules(href string) (WorkloadRules, illumioapi.APIResponse, error) {
	var api illumioapi.APIResponse
	// Active IP Lists
	apiURL, err := url.Parse("https://" + pce.FQDN + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/active/policy_view")
	if err != nil {
		return WorkloadRules{}, api, fmt.Errorf("get iplist - %s", err)
	}
	q := apiURL.Query()
	q.Set("workload", href)
	q.Set("max_api_version", "15")
	apiURL.RawQuery = q.Encode()
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return WorkloadRules{}, api, fmt.Errorf("get iplist - %s", err)
	}
	var workloadrules WorkloadRules
	json.Unmarshal([]byte(api.RespBody), &workloadrules)

	// Return if less than 500
	return workloadrules, api, nil
}

func whichprotocol(proto int) string {
	if proto == 6 {
		return "TCP"
	} else if proto == 12 {
		return "UDP"
	} else {
		return "%"
	}
}

func formatips(ips string) string {
	if ips == "0.0.0.0/0" {
		ips = "%"
	}
	return ips
}

func loadRules(rules WorkloadRules) [][]string {

	ipsets := make(map[string][]string)

	for _, allsets := range rules.Sets.Networks {
		if allsets.Type == "ipv4" {
			for _, wkldipsets := range allsets.Sets {
				ipsets[wkldipsets.ID] = wkldipsets.Ips
			}
		}

	}

	var data [][]string

	for _, ingressrules := range rules.WorkloadInstructions[0].NetworkAccess.Sb.Ingress {
		for _, pp := range ingressrules.Pp {
			//proto := whichprotocol(pp.Proto)
			for _, ps := range ingressrules.PeerSets {
				if len(ipsets[ps]) == 0 {
					continue
				}
				for _, tmpips := range ipsets[ps] {
					ips := formatips(tmpips)
					for _, port := range pp.Port {
						if port == "" {
							port = "%"
						}
						//data = append(data, []string{"%", "%", ips, "%", "%", port, proto})
						data = append(data, []string{"%", "%", ips, "%", "%", port})
					}
				}

			}

		}
	}

	for _, egressrules := range rules.WorkloadInstructions[0].NetworkAccess.Sb.Egress {
		for _, pp := range egressrules.Pp {
			for _, ps := range egressrules.PeerSets {

				//proto := whichprotocol(pp.Proto)
				if len(ipsets[ps]) == 0 {
					continue
				}
				for _, tmpips := range ipsets[ps] {
					ips := formatips(tmpips)
					for _, port := range pp.Port {
						if port == "" {
							port = "%"
						}
						//data = append(data, []string{"%", "%", "%", ips, port, "%",proto})
						data = append(data, []string{"%", "%", "%", ips, port, "%"})

					}
				}

			}

		}

	}
	return data
}

func wkldpolicyexport() {
	// Log start of run
	utils.LogStartCommand("wkld-policy")

	// Get all workloads from the source PCE
	wklds, a, err := pce.GetWkldHostMap()
	utils.LogAPIResp("GetAllWorkloads", a)
	if err != nil {
		utils.LogError(err.Error())
	}
	wkld := illumioapi.Workload{}
	if val, ok := wklds[wkldname]; !ok {
		utils.LogError(fmt.Sprintf("Could not find host.  Please check capitalizations or spelling.\r\n"))
	} else {
		wkld = val
	}
	rules, a, err := GetWorkloadRules(wkld.Href)
	utils.LogAPIResp("GetWorkloadRules", a)
	if err != nil {
		utils.LogError(err.Error())
	}
	if console {
		fmt.Printf("Printing Policy for workload - %s\r\n", wkld.Hostname)
	}
	if console {
		viper.Set("output_format", "both")
	}
	data := loadRules(rules)

	// Write the CSV data
	if csvFile == "" {
		outputFileName = fmt.Sprintf("workloader-traffic-%s.csv", time.Now().Format("20060102_150405"))
	}
	utils.WriteOutput(data, data, csvFile)
}
