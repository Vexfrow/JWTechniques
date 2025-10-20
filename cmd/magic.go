package cmd

import (
	"JWTechniques/attacks"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	jwtStr     string
	userHeader string
	userValue  string
	publicKey  string
	url        string
)

// magicCmd represents the magic command
// Todo : Change description
var magicCmd = &cobra.Command{
	Use:   "magic",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if jwtStr != "" {
			attacks.MainMagic(jwtStr, userHeader, userValue, publicKey, url)
		} else {
			fmt.Print("A token must be given with the \"--token\" (or\"-t\") flag")
		}

	},
}

func init() {
	rootCmd.AddCommand(magicCmd)

	magicCmd.Flags().StringVarP(&jwtStr, "token", "t", "", "The token that must be analyzed")
	magicCmd.Flags().StringVarP(&userHeader, "userHeader", "a", "", "The name of the field containing the username. If no value is given, the tool will check for \"username\" and \"user\" fields")
	magicCmd.Flags().StringVarP(&userValue, "userValue", "v", "admin", "The name that should replaced the current username")
	magicCmd.Flags().StringVarP(&publicKey, "publicKey", "k", "", "A file containing a public key that may be exploited for algorithm confusion attack")
	magicCmd.Flags().StringVarP(&publicKey, "url", "u", "", "The url of the server that will store the key for the JKU header injection ")
}
