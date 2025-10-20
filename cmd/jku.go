package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// jkuCmd represents the jku command
var jkuCmd = &cobra.Command{
	Use:   "jku",
	Short: "",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("jku called")
	},
}

func init() {
	rootCmd.AddCommand(jkuCmd)

	jkuCmd.Flags().BoolP("token", "t", false, "Token")
	jkuCmd.Flags().BoolP("server", "s", true, "Launch server that will serve the file")
}
