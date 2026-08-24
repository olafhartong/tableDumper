package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	httpClient := newHTTPClient(cfg.Timeout, cfg.InsecureSkipVerify)
	messages := make([]string, 0, 2)

	if hasQueryInput(cfg) {
		query, err := readQuery(cfg.Query, cfg.QueryFile)
		if err != nil {
			return err
		}

		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		body, response, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, query)
		if err != nil {
			return err
		}

		if err := writeJSONFile(cfg.Output, body); err != nil {
			return err
		}

		rowCount := len(response.Results)
		message := fmt.Sprintf("wrote %d rows to %s using %s authentication", rowCount, cfg.Output, authMode)
		if cfg.ADXExport {
			dataPath, schemaPath, err := writeADXArtifacts(cfg, response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nadx data file: %s\nadx schema file: %s", dataPath, schemaPath)
		}
		if cfg.OpenGraphExport {
			openGraphPath, iconPath, err := writeOpenGraphArtifact(cfg, response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nopengraph file: %s", openGraphPath)
			if iconPath != "" {
				message += fmt.Sprintf("\nopengraph icon file: %s", iconPath)
			}
			if cfg.BloodHoundUploadGenerated {
				jobID, err := uploadFileToBloodHound(ctx, httpClient, cfg, openGraphPath)
				if err != nil {
					return err
				}
				message += fmt.Sprintf("\nbloodhound graph upload job: %d", jobID)
				if iconPath != "" {
					created, updated, err := uploadCustomNodesToBloodHound(ctx, httpClient, cfg, iconPath)
					if err != nil {
						return err
					}
					message += fmt.Sprintf("\nbloodhound icon upload: created %d, updated %d", created, updated)
				}
			}
		}
		messages = append(messages, message)
	}

	if cfg.DumpTable != "" {
		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		output, err := dumpTable(ctx, httpClient, cfg, token, stderr)
		if err != nil {
			return err
		}

		message := fmt.Sprintf("dumped %d rows from %s over %s to %s using %s authentication", output.Rows, cfg.DumpTable, cfg.DumpLookback, cfg.Output, authMode)
		if output.Stats.Chunks > 1 {
			message += fmt.Sprintf("\nprocessed %d chunk(s) across %d hash partition(s); initial matching row count was %d", output.Stats.Chunks, output.Stats.Partitions, output.Stats.TotalRows)
		}
		if output.ADXDataPath != "" {
			message += fmt.Sprintf("\nadx data file: %s\nadx schema file: %s", output.ADXDataPath, output.ADXSchemaPath)
		}
		if cfg.OpenGraphExport {
			openGraphPath, iconPath, err := writeOpenGraphArtifact(cfg, output.Response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nopengraph file: %s", openGraphPath)
			if iconPath != "" {
				message += fmt.Sprintf("\nopengraph icon file: %s", iconPath)
			}
		}
		messages = append(messages, message)
	}

	if cfg.ADXUploadFile != "" {
		rowsUploaded, batchesUploaded, authMode, err := uploadFileToADX(ctx, httpClient, cfg)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded %d rows from %s to %s/%s in %d batch(es) using %s authentication", rowsUploaded, cfg.ADXUploadFile, cfg.ADXDatabase, cfg.ADXTable, batchesUploaded, authMode))
	}
	if cfg.BloodHoundUploadFile != "" {
		jobID, err := uploadFileToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded %s to BloodHound as file upload job %d", cfg.BloodHoundUploadFile, jobID))
	}
	if cfg.BloodHoundUploadIconsFile != "" {
		created, updated, err := uploadCustomNodesToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadIconsFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded BloodHound custom node icons from %s (created %d, updated %d)", cfg.BloodHoundUploadIconsFile, created, updated))
	}

	if len(messages) == 0 {
		return errors.New("no action requested; provide -query or -query-file to run Defender query, -dump-table to dump a Defender table, -adx-upload-file to ingest data into ADX, or BloodHound upload flags to send OpenGraph artifacts")
	}

	fmt.Fprintln(stdout, strings.Join(messages, "\n"))
	return nil
}
