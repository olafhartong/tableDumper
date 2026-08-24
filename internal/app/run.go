package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	httpClient := newHTTPClient(cfg.Timeout, cfg.InsecureSkipVerify)
	messages := make([]string, 0, 2)
	var pseudonyms *pseudonymizer
	collectionCompleted := false
	if cfg.Pseudonymize {
		pseudonymFields := cfg.PseudonymFields
		usingTableDefaults := pseudonymFields == ""
		if usingTableDefaults {
			pseudonymFields = defaultPseudonymFieldsForTable(cfg.DumpTable)
		}
		fieldPolicy, err := newPseudonymFieldPolicy(pseudonymFields)
		if err != nil {
			return fmt.Errorf("configure pseudonym fields: %w", err)
		}
		var replacements *wordReplacementSet
		if cfg.PseudonymReplacementsFile != "" {
			replacements, err = loadWordReplacementSet(cfg.PseudonymReplacementsFile)
			if err != nil {
				return err
			}
		}
		pseudonyms, err = newPseudonymizer(cfg.PseudonymMap)
		if err != nil {
			return err
		}
		if err := pseudonyms.ConfigureFieldPolicy(fieldPolicy); err != nil {
			return err
		}
		pseudonyms.ConfigureFilenamePseudonymization(cfg.PseudonymizeFilenames)
		fmt.Fprintf(stderr, "[i] pseudonymization enabled; secure mapping file: %s\n", pseudonyms.Path())
		if cfg.PseudonymizeFilenames {
			fmt.Fprintln(stderr, "[i] linked filename pseudonymization enabled for filename, path, and process command-line fields.")
		}
		if discarded := pseudonyms.DiscardedMappingCount(); discarded > 0 {
			fmt.Fprintf(stderr, "[i] removed %d unusable empty legacy mapping(s) while loading the pseudonym vault.\n", discarded)
		}
		if usingTableDefaults && cfg.DumpTable != "" {
			fmt.Fprintf(stderr, "[i] using built-in pseudonym field policy for table %s.\n", cfg.DumpTable)
		} else if usingTableDefaults {
			fmt.Fprintf(stderr, "[i] using built-in fallback pseudonym field policy.\n")
		} else {
			fmt.Fprintf(stderr, "[i] using overridden pseudonym field policy: %s\n", pseudonymFields)
		}
		if replacements != nil {
			if err := pseudonyms.ConfigureWordReplacements(replacements); err != nil {
				return err
			}
			fmt.Fprintf(stderr, "[i] loaded %d literal pseudonym replacement(s) from %s\n", replacements.Len(), cfg.PseudonymReplacementsFile)
		}
	}

	if hasQueryInput(cfg) {
		query, err := readQuery(cfg.Query, cfg.QueryFile)
		if err != nil {
			return err
		}

		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		output, err := dumpQuery(ctx, httpClient, cfg, token, query, pseudonyms, stderr)
		if err != nil {
			return err
		}

		message := fmt.Sprintf("[=] Done. Wrote %d rows to %s using %s authentication", output.Rows, cfg.Output, authMode)
		if output.Stats.Chunks > 1 {
			message += fmt.Sprintf("\n[i] processed %d chunk(s) across %d hash partition(s); query returned %d row(s)", output.Stats.Chunks, output.Stats.Partitions, output.Stats.TotalRows)
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
		collectionCompleted = true
	}

	if cfg.DumpTable != "" {
		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		output, err := dumpTable(ctx, httpClient, cfg, token, pseudonyms, stderr)
		if err != nil {
			return err
		}

		message := fmt.Sprintf("[=] Done! Dumped %d rows from %s over %s to %s using %s authentication", output.Rows, cfg.DumpTable, cfg.DumpLookback, cfg.Output, authMode)
		if output.Stats.Chunks > 1 {
			message += fmt.Sprintf("\n[i] processed %d chunk(s) across %d hash partition(s); initial matching row count was %d", output.Stats.Chunks, output.Stats.Partitions, output.Stats.TotalRows)
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
		collectionCompleted = true
	}

	if cfg.ADXUploadFile != "" {
		rowsUploaded, batchesUploaded, authMode, err := uploadFileToADX(ctx, httpClient, cfg)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("[i] uploaded %d rows from %s to %s/%s in %d batch(es) using %s authentication", rowsUploaded, cfg.ADXUploadFile, cfg.ADXDatabase, cfg.ADXTable, batchesUploaded, authMode))
	}
	if cfg.BloodHoundUploadFile != "" {
		jobID, err := uploadFileToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("[i] uploaded %s to BloodHound as file upload job %d", cfg.BloodHoundUploadFile, jobID))
	}
	if cfg.BloodHoundUploadIconsFile != "" {
		created, updated, err := uploadCustomNodesToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadIconsFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("[i] uploaded BloodHound custom node icons from %s (created %d, updated %d)", cfg.BloodHoundUploadIconsFile, created, updated))
	}

	if len(messages) == 0 {
		return errors.New("no action requested; provide -query or -query-file to run Defender query, -dump-table to dump a Defender table, -adx-upload-file to ingest data into ADX, or BloodHound upload flags to send OpenGraph artifacts")
	}
	if collectionCompleted && pseudonyms != nil {
		kept, err := finalizePseudonymMap(pseudonyms, cfg.PseudonymMapRetention)
		if err != nil {
			return err
		}
		if kept {
			messages = append(messages, fmt.Sprintf("[i] pseudonym mapping file kept at %s (%d total mappings, %d added this run)", pseudonyms.Path(), pseudonyms.MappingCount(), pseudonyms.NewMappingCount()))
		} else {
			messages = append(messages, "[i] pseudonym mapping file deleted")
		}
	}

	fmt.Fprintln(stdout, strings.Join(messages, "\n"))
	return nil
}
