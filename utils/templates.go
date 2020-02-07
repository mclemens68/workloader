package utils

// RootTemplate returns the root usage template
func RootTemplate() string {
	return `  Usage:{{if .Runnable}}
	{{.CommandPath}} [command]

  PCE Management Commands:{{range .Commands}}{{if (or (eq .Name "pce-remove") (eq .Name "pce-add") (eq .Name "get-default") (eq .Name "set-default") (eq .Name "pce-list"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

  Import/Export Commands:{{range .Commands}}{{if (or (eq .Name "wkld-import") (eq .Name "wkld-export") (eq .Name "ipl-export") (eq .Name "ipl-import") (eq .Name "flow-import") (eq .Name "label-rename"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
	  
  Automated Labeling Commands:{{range .Commands}}{{if (or (eq .Name "traffic") (eq .Name "subnet") (eq .Name "hostparse"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

  Workload Management Commands:{{range .Commands}}{{if (or (eq .Name "compatibility") (eq .Name "mode") (eq .Name "upgrade") (eq .Name "unpair") (eq .Name "delete"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

  Reporting Commands:{{range .Commands}}{{if (or (eq .Name "mislabel") (eq .Name "dupecheck") (eq .Name "flowsummary") (eq .Name "explorer") (eq .Name "nic"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

  PCE-to-PCE Commands:{{range .Commands}}{{if (or (eq .Name "wkld-to-ipl"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

  Version Command:{{range .Commands}}{{if (or (eq .Name "version"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
  
Use "{{.CommandPath}} [command] --help" for more information on a command.{{end}}

  `
}

// SubCmdTemplate returns the usage template used for all subcommands
func SubCmdTemplate() string {
	return `
  Usage:{{if .Runnable}}
    {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
    {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}
  
  Aliases:
    {{.NameAndAliases}}{{end}}{{if .HasExample}}
  
  Examples:
  {{.Example}}{{end}}{{if .HasAvailableSubCommands}}
  
  Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
    {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
  
  Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}
  
  Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}
  
  Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
	{{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}
  
  Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
  
`
}

// SRootCmdTemplate returns the usage template for sub root commands
func SRootCmdTemplate() string {
	return `
  Usage:{{if .Runnable}}
    {{.CommandPath}} [sub-command]{{end}}{{if gt (len .Aliases) 0}}
  
  Aliases:
    {{.NameAndAliases}}{{end}}{{if .HasExample}}
  
  Examples:
  {{.Example}}{{end}}{{if .HasAvailableSubCommands}}
  
  Available Sub-Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
    {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
  
  Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}
  
  Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
  
`
}
