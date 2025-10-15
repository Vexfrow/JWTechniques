package cmd

import (
	"JWTechniques/attacks"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	jwtStr string
)

// magicCmd represents the magic command
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
			attacks.MainMagic(jwtStr)
		} else {
			fmt.Print("A token must be given with the \"--token\" (or\"-t\") flag")
		}

	},
}

func init() {
	rootCmd.AddCommand(magicCmd)

	magicCmd.Flags().StringVarP(&jwtStr, "token", "t", "", "The token that must be analyzed")
}
