/*
Copyright © 2021 JEFFREY AVEN jeffrey.aven@gammadata.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// logsCmd represents the logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "The Okta System Log records system events that are related to your organization.",
	Long: `
The Okta System Log records system events that are related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. For example:

okta-admin logs get
	`,
	Args: cobra.MinimumNArgs(1),
}

//
// Output Operations (return data)
//

// okta-admin logs get
var getLogsCmd = &cobra.Command{
	Use:   "get",
	Short: "The Okta System Log API provides read access to your organization’s system log.",
	Long:  `The Okta System Log API provides read access to your organization’s system log. This API provides more functionality than the Events API.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		queryParams := retQueryParams(filter)
		log.Printf("Getting logs for %s", viper.GetString("org"))
		ctx, client := getOrCreateClient()
		processOutput(client.LogEvent.GetLogs(ctx, queryParams))
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)
	// add sub commands
	logsCmd.AddCommand(getLogsCmd)
	// generateMarkdownDocs(usersCmd, "./docs/logs/")

}
