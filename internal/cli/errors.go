package cli

import (
	"errors"
	"fmt"

	"github.com/envrune/envrune/internal/app"
	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/dotenv"
	"github.com/envrune/envrune/internal/exporter"
	"github.com/envrune/envrune/internal/generator"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
	"github.com/envrune/envrune/internal/vault"
)

// describe turns an error into a message that says what went wrong. Names of
// references, variables and environments are metadata and may be shown;
// secret values never reach an error.
func describe(err error, fallback string) string {
	var busy *vault.BusyError
	var missingSecret *app.MissingSecretError
	var missingEnvironment *app.MissingEnvironmentError
	var notFound *runner.CommandNotFoundError
	var exit *runner.ExitError
	var start *runner.StartError
	switch {
	case errors.As(err, &busy):
		if busy.PID > 0 {
			return fmt.Sprintf("The vault is in use by another process (PID %d). Try again in a moment.", busy.PID)
		}
		return "The vault is in use by another process. Try again in a moment."
	case errors.Is(err, vault.ErrCannotUnlock):
		return "Unable to unlock the vault: the master password is wrong or the vault file is damaged."
	case errors.Is(err, vault.ErrNotFound):
		return "No vault was found. Run `envrune init` to create one."
	case errors.Is(err, vault.ErrAlreadyExists):
		return "A vault already exists."
	case errors.Is(err, vault.ErrReplaced):
		return "The vault file was replaced by another process. Lock this session and unlock it again."
	case errors.As(err, &missingSecret):
		return sentence(err.Error()) + " Store it with `envrune set <reference>`."
	case errors.As(err, &missingEnvironment):
		return sentence(err.Error())
	case errors.As(err, &notFound):
		return fmt.Sprintf("Command not found: %s", notFound.Name)
	case errors.As(err, &exit), errors.As(err, &start):
		return sentence(err.Error())
	case errors.Is(err, app.ErrSessionClosed):
		return "The session is locked."
	case errors.Is(err, app.ErrPasswordConfirmation):
		return "The master passwords do not match."
	case errors.Is(err, ErrValueConfirmation):
		return "The two values do not match. Nothing was stored."
	case errors.Is(err, ErrMultilineInput):
		return "The input had more than one line, so it was discarded. Paste the value on its own."
	case errors.Is(err, ErrSecureInputRequired):
		return "Secure interactive input is required."
	case errors.Is(err, domain.ErrInvalidReference):
		return "Invalid secret reference. Use lowercase dot-separated segments, such as openai.personal."
	case errors.Is(err, project.ErrNotFound):
		return "No Envrune project configuration (envrune.yml) was found."
	case errors.Is(err, project.ErrInvalidConfig):
		return "Invalid variable name or project configuration. Variables look like OPENAI_API_KEY."
	case errors.Is(err, project.ErrProjectBusy):
		return "envrune.yml is being updated by another process. Try again."
	case errors.Is(err, app.ErrInvalidImport), errors.Is(err, dotenv.ErrInvalid), errors.Is(err, dotenv.ErrDuplicate):
		return "The dotenv input has an invalid or duplicated variable."
	case errors.Is(err, generator.ErrInvalidLength):
		return "Invalid generated value length."
	case errors.Is(err, exporter.ErrExists):
		return "The export destination already exists. Use --force to replace it."
	case errors.Is(err, exporter.ErrInvalidValue):
		return "A value cannot be written to a dotenv file."
	}
	return fallback
}

func sentence(message string) string {
	if message == "" {
		return message
	}
	if message[0] >= 'a' && message[0] <= 'z' {
		message = string(message[0]-'a'+'A') + message[1:]
	}
	return message + "."
}
