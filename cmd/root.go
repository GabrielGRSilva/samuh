package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Version, Commit and Date are overridden at build time via -ldflags.
var (
	Version = "0.0.2 - dev"
	Commit  = "none"
	Date    = "10/14/2026"
)

var rootCmd = &cobra.Command{
	Use:   "samuh",
	Short: "SAMUH - Secure Application Makes U Happy",
	Long:  "SAMUH (Secure Application Makes U Happy) — Security vulnerability scanner for PHP, Node.js, and JS/TS projects",
}

var (
	verbose bool
	quiet   bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all output except errors and final report")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
