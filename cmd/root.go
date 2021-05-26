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
	"context"
	"fmt"
	"log"
	"os"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
)

var cfgFile string
var filter string
var jsonquery string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "okta-admin",
	Short: "A brief description of your application",
	Long: `
	______     __  __     ______   ______     ______     _____     __    __     __     __   __    
	/\  __ \   /\ \/ /    /\__  _\ /\  __ \   /\  __ \   /\  __-.  /\ "-./  \   /\ \   /\ "-.\ \   
	\ \ \/\ \  \ \  _"-.  \/_/\ \/ \ \  __ \  \ \  __ \  \ \ \/\ \ \ \ \-./\ \  \ \ \  \ \ \-.  \  
	 \ \_____\  \ \_\ \_\    \ \_\  \ \_\ \_\  \ \_\ \_\  \ \____-  \ \_\ \ \_\  \ \_\  \ \_\\"\_\ 
	  \/_____/   \/_/\/_/     \/_/   \/_/\/_/   \/_/\/_/   \/____/   \/_/  \/_/   \/_/   \/_/ \/_/ 

	`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// check env vars
	checkEnvVar("OKTAORGURL")
	checkEnvVar("OKTAAPITOKEN")

	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.okta-admin.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.BindEnv("org", "OKTAORGURL")
	viper.BindEnv("apitoken", "OKTAAPITOKEN")
}

// check that required envrironment variables are set
func checkEnvVar(envvar string) {
	if len(os.Getenv(envvar)) == 0 {
		fmt.Printf("Environment variable [%s] must be set", envvar)
		os.Exit(1)
	}
}

//
// Common functions
//
func getOrCreateClient() (oktaCtx context.Context, oktaClient *okta.Client) {
	org := viper.GetString("org")
	apitoken := viper.GetString("apitoken")
	oktaCtx, oktaClient, err := okta.NewClient(context.Background(), okta.WithOrgUrl(org), okta.WithToken(apitoken))
	if err != nil {
		panic(err)
	}
	return
}

func retQueryParams(filter string) (queryParams *query.Params) {
	// API filter
	queryParams = query.NewQueryParams()
	if len(filter) != 0 {
		// filter set
		log.Printf("Filter specified: %s", filter)
		queryParams = query.NewQueryParams(query.WithFilter(filter))
	}
	return
}

func retResults(data []byte, jsonquery string) {
	// Json query
	if len(jsonquery) != 0 {
		// jsonquery set
		log.Printf("Json query specified: %s", jsonquery)
		res := gjson.Get(string(data), jsonquery)
		fmt.Println(res)
	} else {
		fmt.Println(string(data))
	}
}

func generateMarkdownDocs(cmd *cobra.Command, path string) {
	err := doc.GenMarkdownTree(cmd, path)
	if err != nil {
		panic(err)
	}
}
