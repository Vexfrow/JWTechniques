package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "JWTechniques",
	Short: "JWTechniques is a little tool to manipulate JWT and generate tokens that may exploit vulnerable JWT verification systems",
	Long:  `JWTechniques provides several means to generate exploitable JWT`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
