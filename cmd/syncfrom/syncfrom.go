package syncfrom

import (
	"fmt"

	"github.com/brian1917/workloader/cmd/syncfrom/clouds"
	"github.com/spf13/cobra"
)

// SyncFromCmd provides a mechanism to import data from cloud provider.  Aws or Azure - different options are required to access the cloud instance.
var SyncFromCmd = &cobra.Command{
	Use:   "syncfrom",
	Short: "Import Cloud instances as unmanaged workloads. Requires subcommands that represent the cloud info will be imported from.",
	Long: `
Impoer Cloud instances into PCE as UMWL.  Currently support AWS and Azure`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Command requires a sub command: aws or azure")
	},
}

func init() {

	// Disable sorting
	cobra.EnableCommandSorting = false

	// Add all commands
	// Top layer commands awsimport or azureimport
	SyncFromCmd.AddCommand(clouds.AwsSyncCmd)
	SyncFromCmd.AddCommand(clouds.AzureSyncCmd)
	SyncFromCmd.AddCommand(clouds.VCenterSyncCmd)

}
