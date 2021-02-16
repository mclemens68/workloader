package cloud

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
	"github.com/jdschmitz15/integrator/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CloudImportCmd provides a mechanism to import data from cloud provider.  Aws or Azure - different options are required to access the cloud instance.
var CloudImportCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Import Cloud instances as unmanaged workloads. Requires subcommands that represent the cloud info will be imported from.",
	Long: `
Impoer Cloud instances into PCE as UMWL.  Currently support AWS and Azure`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Command requires a sub command: awsimport or azureimport")
	},
}

var awsCredsFile, awsRegion, awsUserID, awsSecret, awsToken, awsMatchField string
var azureRegion, azureRG, azureUserid, azureSecret, azureMatchField string
var csvFile string
var umwl, debug, updatePCE, noPrompt, keepTempFile, fqdnToHostname, keepAllPCEInterfaces bool
var pce illumioapi.PCE
var err error

// Init builds the commands
func init() {

	// Disable sorting
	cobra.EnableCommandSorting = false

	// Top layer commands awsimport or azureimport
	CloudImportCmd.AddCommand(AwsImportCmd)
	CloudImportCmd.AddCommand(AzureImportCmd)

	//awsimport options
	AwsImportCmd.Flags().StringVarP(&awsCredsFile, "aws-credsfile", "c", "", "AWS credential file location(default - Mac -\"~/.aws/credentials\" Windows - \"%homedrive%%homepath%\\.aws\\credentials\"")
	AwsImportCmd.Flags().StringVarP(&awsRegion, "aws-region", "r", "us-east-2", "AWS region that will be used to sync data with the PCE (default - \"us-east-2\"")
	AwsImportCmd.Flags().StringVarP(&awsUserID, "aws-userid", "u", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS username")
	AwsImportCmd.Flags().StringVarP(&awsSecret, "aws-secret", "p", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS password")
	AwsImportCmd.Flags().StringVarP(&awsToken, "aws-token", "t", "", "By default looks for AWS CLI created ~./aws/credentials file with user creds - can override with AWS token")
	AwsImportCmd.Flags().StringVarP(&awsMatchField, "aws-match-field", "m", "", "ServiceNow field name to match to Illumio hostname")
	AwsImportCmd.Flags().BoolVar(&umwl, "umwl", false, "Create unmanaged workloads for non-matches.")
	AwsImportCmd.Flags().BoolVarP(&keepTempFile, "keep-temp-file", "k", false, "Do not delete the temp CSV file downloaded from SerivceNow.")
	AwsImportCmd.Flags().BoolVarP(&fqdnToHostname, "fqdn-to-hostname", "f", false, "Convert FQDN hostnames reported by Illumio VEN to short hostnames by removing everything after first period (e.g., test.domain.com becomes test). ")
	AwsImportCmd.Flags().BoolVarP(&keepAllPCEInterfaces, "keep-all-pce-interfaces", "s", false, "Will not delete an interface on an unmanaged workload if it's not in the import. It will only add interfaces to the workload.")
	//AwsImportCmd.MarkFlagRequired("aws-credsfile")
	AwsImportCmd.Flags().SortFlags = false

	//azureimport options
	AzureImportCmd.Flags().StringVarP(&azureRegion, "azure-region", "", "", "Filter VMs based on Azure region that will be used to sync data with the PCE (default - \"us-east-2\"")
	AzureImportCmd.Flags().StringVarP(&azureRG, "azure-resourcegroup", "", "", "The Azure resource group you want to import.  If left blank all resource groups selected")
	AzureImportCmd.Flags().StringVarP(&azureUserid, "azure-user", "u", "", "ServiceNow username")
	AzureImportCmd.Flags().StringVarP(&azureSecret, "azure-secret", "p", "", "ServiceNow password")
	AzureImportCmd.Flags().StringVarP(&azureMatchField, "azure-match-field", "m", "", "ServiceNow field name to match to Illumio hostname")
	AzureImportCmd.Flags().BoolVar(&umwl, "umwl", false, "Create unmanaged workloads for non-matches.")
	AzureImportCmd.Flags().BoolVarP(&keepTempFile, "keep-temp-file", "k", false, "Do not delete the temp CSV file downloaded from SerivceNow.")
	AzureImportCmd.Flags().BoolVarP(&fqdnToHostname, "fqdn-to-hostname", "f", false, "Convert FQDN hostnames reported by Illumio VEN to short hostnames by removing everything after first period (e.g., test.domain.com becomes test). ")
	AzureImportCmd.Flags().BoolVarP(&keepAllPCEInterfaces, "keep-all-pce-interfaces", "s", false, "Will not delete an interface on an unmanaged workload if it's not in the import. It will only add interfaces to the workload.")
	AzureImportCmd.Flags().SortFlags = false

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

// AzureImportCmd checks if the keyfilename is entered.
var AzureImportCmd = &cobra.Command{
	Use:   "azureimport",
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

		utils.LogStartCommand("azureimport")

		//load keymapfile, pull data from Azure, use that data to import into PCE.
		keyMap := readKeyFile(csvFile)
		callWkldImport("azure", azureHTTP(keyMap))
	},
}

// AwsImportCmd checks if the keyfilename is entered.
var AwsImportCmd = &cobra.Command{
	Use:   "awsimport",
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

		utils.LogStartCommand("awsimport")

		//load keymapfile, pull data from Azure, use that data to import into PCE.
		keyMap := readKeyFile(csvFile)
		callWkldImport("aws", awsHTTP(awsRegion, keyMap))
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
	utils.LogEndCommand("awsimport")
}
