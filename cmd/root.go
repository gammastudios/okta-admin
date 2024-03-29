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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
var format bool

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
	rootCmd.PersistentFlags().StringVarP(&jsonquery, "jsonquery", "q", "", "Json query to extract specified fields from a response object ()")
	rootCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "filter expression to filter results (e.g. 'status eq \\\"ACTIVE\\\"')")

	rootCmd.PersistentFlags().BoolVar(&format, "format", false, "format (pretty-print) json output")

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
func generateRandomString(strLength int) (string, error) {
	b := make([]byte, strLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	} else {
		return base64.URLEncoding.EncodeToString(b), nil
	}
}

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

func retResults(data interface{}, jsonquery string) {
	// Marshal
	var b []byte
	var err error
	if format {
		b, err = json.MarshalIndent(data, "", " ")
		if err != nil {
			panic(err)
		}
	} else {
		b, err = json.Marshal(data)
		if err != nil {
			panic(err)
		}
	}
	// Json query
	if len(jsonquery) != 0 {
		// jsonquery set
		log.Printf("Json query specified: %s", jsonquery)
		res := gjson.Get(string(b), jsonquery)
		fmt.Println(res)
	} else {
		fmt.Println(string(b))
	}
}

func processOutput(data interface{}, resp *okta.Response, err error) {
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Println(resp.Status)
		if data != nil {
			retResults(data, jsonquery)
		}
	}
}

func processHttpOutput(url string, jsonData []byte) {
	org := viper.GetString("org")
	apitoken := viper.GetString("apitoken")
	reqBody := bytes.NewReader(jsonData)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s", org, url), reqBody)
	req.Header.Set("Authorization", fmt.Sprintf("SSWS %s", apitoken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	} else {
		log.Println(resp.Status)
	}
	defer resp.Body.Close()
	//Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	} else {
		fmt.Printf(string(respBody))
	}
}

func generateMarkdownDocs(cmd *cobra.Command, path string) {
	err := doc.GenMarkdownTree(cmd, path)
	if err != nil {
		panic(err)
	}
}
