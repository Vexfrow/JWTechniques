package cmd

import (
	"JWTechniques/attacks"
	"fmt"
	"os"

	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	jwtStr    string
	publicKey string
	url       string
)

// magicCmd represents the magic command
var magicCmd = &cobra.Command{
	Use:   "magic",
	Short: "Generate several JWT that may exploit vulnerabilities, from a single JWT",
	Long:  ``,

	Run: func(cmd *cobra.Command, args []string) {
		if jwtStr != "" {
			attacks.MainMagic(jwtStr, publicKey, url)
		} else {
			fmt.Print("A token must be provided with the \"--token\" (or\"-t\") flag\n")
		}

	},
}

func PrintHelp() {
	fmt.Print(`
Magic takes a JWT, analyze it and then craft several admin-privileged tokens that may exploit potential vulnerabilities on remote server.

The vulnerabilities tested are:
		- The None algorithm attack
		- The public key header injection
		- The JKU header injection
		- The KID header injection
		- The algorithm confusion attack

In some cases, some flags are needed :
`)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "--token\t-t\tMandatory\tThe original JWT")
	fmt.Fprintln(w, "--userHeader\t-a\tOptional\tThe header that must be modified to become admin")
	fmt.Fprintln(w, "--userValue\t-v\tOptional\tThe value that must be used to become admin")
	fmt.Fprintln(w, "--publicKey\t-k\tMandatory only for algorithm confusion attack\tA file containing the public key used to validate the token signature")
	fmt.Fprintln(w, "--url\t-u\tMandatory only for JKU header injection\tThe URL linking to the server hosting the file")

	w.Flush()

}

func init() {
	rootCmd.AddCommand(magicCmd)

	magicCmd.Flags().StringVarP(&jwtStr, "token", "t", "", "The token that must be analyzed")
	magicCmd.Flags().StringVarP(&attacks.UserHeader, "userHeader", "a", "", "The name of the field containing the username. If no value is given, the tool will check for \"username\" and \"user\" fields")
	magicCmd.Flags().StringVarP(&attacks.UserValue, "userValue", "v", "admin", "The name that should replaced the current username")
	magicCmd.Flags().StringVarP(&publicKey, "publicKey", "k", "", "A file containing a public key that may be exploited for algorithm confusion attack")
	magicCmd.Flags().StringVarP(&url, "url", "u", "", "The url of the server that will store the key for the JKU header injection ")
}
