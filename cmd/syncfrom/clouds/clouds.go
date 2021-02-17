package clouds

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/brian1917/illumioapi"
	"github.com/brian1917/workloader/cmd/wkldimport"
	"github.com/brian1917/workloader/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var credsFile, region, userID, secret, token, rg string

var csvFile string
var ignoreState, umwl, ignorePublic, debug, updatePCE, noPrompt, keepTempFile, fqdnToHostname, keepAllPCEInterfaces bool
var pce illumioapi.PCE
var err error

// Init builds the commands
func init() {

	// Disable sorting
	cobra.EnableCommandSorting = false

	//awsimport options
	AwsSyncCmd.Flags().StringVarP(&credsFile, "credsfile", "c", "", "AWS credential file location(default - Mac -\"~/.aws/credentials\" Windows - \"%homedrive%%homepath%\\.aws\\credentials\"")
	AwsSyncCmd.Flags().StringVarP(&region, "region", "r", "us-east-2", "AWS region that will be used to sync data with the PCE (default - \"us-east-2\"")
	AwsSyncCmd.Flags().StringVarP(&userID, "userid", "u", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS username")
	AwsSyncCmd.Flags().StringVarP(&secret, "secret", "p", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS password")
	AwsSyncCmd.Flags().StringVarP(&token, "token", "t", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS token")
	AwsSyncCmd.Flags().BoolVarP(&ignorePublic, "ignore-public", "i", false, "Use to ignore the public IP address on EC2 interfaces")
	AwsSyncCmd.Flags().BoolVarP(&ignoreState, "ignore-state", "", false, "By default only looks for running workloads")
	AwsSyncCmd.Flags().BoolVar(&umwl, "umwl", false, "Create unmanaged workloads for non-matches.")
	AwsSyncCmd.Flags().BoolVarP(&keepTempFile, "keep-temp-file", "k", false, "Do not delete the temp CSV file downloaded from SerivceNow.")
	AwsSyncCmd.Flags().BoolVarP(&fqdnToHostname, "fqdn-to-hostname", "f", false, "Convert FQDN hostnames reported by Illumio VEN to short hostnames by removing everything after first period (e.g., test.domain.com becomes test). ")
	AwsSyncCmd.Flags().BoolVarP(&keepAllPCEInterfaces, "keep-all-pce-interfaces", "s", false, "Will not delete an interface on an unmanaged workload if it's not in the import. It will only add interfaces to the workload.")
	//AwsImportCmd.MarkFlagRequired("aws-credsfile")
	AwsSyncCmd.Flags().SortFlags = false

	//azureimport options
	AzureSyncCmd.Flags().StringVarP(&region, "region", "r", "", "Filter VMs based on Azure region that will be used to sync data with the PCE (default - \"us-east-2\"")
	AzureSyncCmd.Flags().StringVarP(&rg, "resourcegroup", "g", "", "The Azure resource group you want to Sync.  If left blank all resource groups selected")
	AzureSyncCmd.Flags().StringVarP(&userID, "user", "u", "", "ServiceNow username")
	AzureSyncCmd.Flags().StringVarP(&secret, "secret", "p", "", "ServiceNow password")
	AzureSyncCmd.Flags().BoolVarP(&ignorePublic, "public", "i", false, "Use to ignore the public IP address on EC2 interfaces")
	AzureSyncCmd.Flags().BoolVarP(&ignoreState, "ignore-state", "", false, "By default only looks for running instances.  Use this option to select all instances not matter running state")
	AzureSyncCmd.Flags().BoolVar(&umwl, "umwl", false, "Create unmanaged workloads for non-matches.")
	AzureSyncCmd.Flags().BoolVarP(&keepTempFile, "keep-temp-file", "k", false, "Do not delete the temp CSV file downloaded from SerivceNow.")
	AzureSyncCmd.Flags().BoolVarP(&fqdnToHostname, "fqdn-to-hostname", "f", false, "Convert FQDN hostnames reported by Illumio VEN to short hostnames by removing everything after first period (e.g., test.domain.com becomes test). ")
	AzureSyncCmd.Flags().BoolVarP(&keepAllPCEInterfaces, "keep-all-pce-interfaces", "s", false, "Will not delete an interface on an unmanaged workload if it's not in the import. It will only add interfaces to the workload.")
	AzureSyncCmd.Flags().SortFlags = false

}

// read-KeyFile - Reads file that maps TAG names to PCE RAEL labels.   File is added as the first argument.
func readKeyFile(filename string) map[string]string {

	keyMap := make(map[string]string)
	// Open CSV File
	file, err := os.Open(filename)
	if err != nil {
		utils.LogError(err.Error())
	}
	defer file.Close()
	reader := csv.NewReader(utils.ClearBOM(bufio.NewReader(file)))

	// Start the counters
	i := 0

	// Iterate through CSV entries
	for {

		// Increment the counter
		i++

		// Read the line
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			utils.LogError(err.Error())
		}

		// Skip the header row
		if i == 1 {
			continue
		}
		keyMap[line[0]] = line[1]
	}
	return keyMap
}

// AzureSyncCmd checks if the keyfilename is entered.
var AzureSyncCmd = &cobra.Command{
	Use:   "azure",
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

		utils.LogStartCommand("azure-sync")

		//load keymapfile, pull data from Azure, use that data to import into PCE.
		keyMap := readKeyFile(csvFile)
		callWkldImport("azure", azureHTTP(keyMap))
	},
}

// AwsSyncCmd checks if the keyfilename is entered.
var AwsSyncCmd = &cobra.Command{
	Use:   "aws",
	Short: "Integrate AWS EC2 instances into PCE.",
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

		utils.LogStartCommand("aws-sync")

		//load keymapfile, pull data from Azure, use that data to import into PCE.
		keyMap := readKeyFile(csvFile)
		callWkldImport("aws", awsHTTP(region, keyMap))
	},
}

func callWkldImport(cloudName string, allVMs map[string]cloudData) {
	var outputFileName string

	csvData := [][]string{{"hostname", "role", "app", "env", "loc", "interfaces", "name"}}

	for _, instance := range allVMs {

		ipdata := []string{}
		for num, intf := range instance.Interfaces {
			if intf.PublicIP != "" {
				ipdata = append(ipdata, fmt.Sprintf("eth%d:%s", num, intf.PublicIP))
			}
			for _, ips := range intf.PrivateIP {
				ipdata = append(ipdata, fmt.Sprintf("eth%d:%s", num, ips))
			}
		}
		csvData = append(csvData, []string{instance.Name, instance.Tags["role"], instance.Tags["app"], instance.Tags["env"], instance.Tags["loc"], strings.Join(ipdata, ";"), instance.Name})
	}

	if len(csvData) > 1 {
		if outputFileName == "" {
			outputFileName = fmt.Sprintf("workloader-%s-rawdata-%s.csv", cloudName, time.Now().Format("20060102_150405"))
		}
		utils.WriteOutput(csvData, csvData, outputFileName)
		utils.LogInfo(fmt.Sprintf("%d workloads exported", len(csvData)-1), true)
	} else {
		// Log command execution for 0 results
		utils.LogInfo("no cloud instances found for export.", true)
	}

	// Call the workloader import command
	f := wkldimport.FromCSVInput{
		ImportFile:           outputFileName,
		PCE:                  pce,
		MatchIndex:           1,
		RoleIndex:            2,
		AppIndex:             3,
		EnvIndex:             4,
		LocIndex:             5,
		IntIndex:             6,
		NameIndex:            7,
		Umwl:                 umwl,
		KeepAllPCEInterfaces: keepAllPCEInterfaces,
		FQDNtoHostname:       fqdnToHostname,
		UpdatePCE:            updatePCE,
		NoPrompt:             noPrompt,
	}
	wkldimport.FromCSV(f)

	// Delete the temp file
	if !keepTempFile {
		if err := os.Remove(outputFileName); err != nil {
			utils.LogWarning(fmt.Sprintf("Could not delete %s", outputFileName), true)
		} else {
			utils.LogInfo(fmt.Sprintf("Deleted %s", outputFileName), false)
		}
	}
	utils.LogEndCommand(fmt.Sprintf("%s-sync", cloudName))
}
