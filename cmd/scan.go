package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"samuh/internal/analyzer"
	"samuh/internal/engine"
	"samuh/internal/reporter"
	"samuh/internal/rules"

	"github.com/spf13/cobra"

	// Import analyzer packages to trigger their init() registration.
	_ "samuh/internal/analyzer/javascript"
	_ "samuh/internal/analyzer/node"
	_ "samuh/internal/analyzer/php"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project directory for security vulnerabilities",
	Long: `Scan a project directory for security vulnerabilities mapped to
OWASP Top 10:2025 and NIST CSF 2.0. Generates a detailed report
with findings and remediation guidance.

If no path is specified, the current directory is scanned.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runScan,
}

func init() {
	scanCmd.Flags().StringP("scope", "p", "project", "Scan scope: project or folder")
	scanCmd.Flags().StringP("output", "o", "", "Output file path (empty = stdout)")
	scanCmd.Flags().StringP("format", "f", "markdown", "Report format: json, html, markdown, sarif")
	scanCmd.Flags().StringP("severity", "s", "low", "Minimum severity filter: info, low, medium, high, critical")
	scanCmd.Flags().StringSliceP("language", "l", nil, "Force specific language(s), comma-separated")
	scanCmd.Flags().StringSliceP("exclude", "e", nil, "Glob patterns to exclude files/dirs")
	scanCmd.Flags().Bool("no-color", false, "Disable colored output")
	scanCmd.Flags().Int64("max-file-size", 1048576, "Max file size in bytes (capped at 10MB)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	scope, _ := cmd.Flags().GetString("scope")
	out, _ := cmd.Flags().GetString("output")
	formatStr, _ := cmd.Flags().GetString("format")
	sevStr, _ := cmd.Flags().GetString("severity")
	langs, _ := cmd.Flags().GetStringSlice("language")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	maxSize, _ := cmd.Flags().GetInt64("max-file-size")

	scanScope, err := parseScope(scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	format := parseFormat(formatStr)
	minSev := parseSeverity(sevStr)

	const maxFileSizeCap = 10 * 1024 * 1024
	if maxSize > maxFileSizeCap {
		maxSize = maxFileSizeCap
	}
	if maxSize <= 0 {
		maxSize = 1048576
	}

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: path %q does not exist: %v\n", path, err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: path %q is not a directory\n", path)
		os.Exit(1)
	}

	registry := analyzer.DefaultRegistry()

	opts := engine.Options{
		Scope:       scanScope,
		Path:        path,
		Exclude:     excludes,
		Languages:   langs,
		MinSeverity: minSev,
		MaxFileSize: maxSize,
		Verbose:     verbose,
	}

	eng := engine.New(registry, opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if !quiet {
		fmt.Fprintf(os.Stderr, "🛡️  SAMUH — Scanning %s ...\n", path)
	}

	report, err := eng.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", err)
		os.Exit(1)
	}

	rep, err := reporter.New(format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating reporter: %v\n", err)
		os.Exit(1)
	}

	reportBytes, err := rep.Generate(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		os.Exit(1)
	}

	if out != "" {
		out = filepath.Clean(out)
		if err := os.WriteFile(out, reportBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "📄 Report written to %s\n", out)
		}
	} else {
		os.Stdout.Write(reportBytes)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "\n✅ Scan completed in %s\n", report.ScanDuration)
		fmt.Fprintf(os.Stderr, "📊 Found %d finding(s) across %d file(s)\n",
			report.TotalFindings, report.TotalFiles)

		if report.Summary.BySeverity[rules.SeverityCritical] > 0 {
			fmt.Fprintf(os.Stderr, "🔴 %d CRITICAL\n", report.Summary.BySeverity[rules.SeverityCritical])
		}
		if report.Summary.BySeverity[rules.SeverityHigh] > 0 {
			fmt.Fprintf(os.Stderr, "🟠 %d HIGH\n", report.Summary.BySeverity[rules.SeverityHigh])
		}
	}

	// A non-zero exit on critical/high findings lets CI pipelines fail the build.
	if report.Summary.BySeverity[rules.SeverityCritical] > 0 ||
		report.Summary.BySeverity[rules.SeverityHigh] > 0 {
		os.Exit(1)
	}
}
