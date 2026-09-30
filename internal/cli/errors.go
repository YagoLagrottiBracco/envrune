package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/clipboard"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/exporter"
	"github.com/YagoLagrottiBracco/envrune/internal/generator"
	"github.com/YagoLagrottiBracco/envrune/internal/keychain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// describe turns an error into a message that says what went wrong. Names of
// references, variables and environments are metadata and may be shown;
// secret values never reach an error.
func describe(err error, fallback string) string {
	var busy *vault.BusyError
	var missingSecret *app.MissingSecretError
	var invalidVariables *app.InvalidVariablesError
	var missingEnvironment *app.MissingEnvironmentError
	var noEnvironment *app.NoEnvironmentChosenError
	var configErr *project.ConfigError
	var notFound *runner.CommandNotFoundError
	var exit *runner.ExitError
	var start *runner.StartError
	var cloudErr *app.CloudError
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
	case errors.As(err, &invalidVariables):
		return sentence(err.Error()) + " Run `envrune setup` to fix it, or see variables: in envrune.yml."
	case errors.As(err, &missingEnvironment), errors.As(err, &noEnvironment), errors.As(err, &configErr):
		return sentence(err.Error())
	case errors.Is(err, ErrLocked):
		return "The vault is locked. Run `envrune unlock` first."
	case errors.Is(err, app.ErrNoVault):
		return "This command needs your personal vault; only ENVRUNE_IDENTITY is available here."
	case errors.Is(err, app.ErrConsumerValue), errors.Is(err, app.ErrNoCloud):
		return sentence(err.Error())
	case errors.As(err, &cloudErr):
		// Names organizations, environments, and secrets, never a value.
		return sentence(strings.TrimRight(err.Error(), "."))
	case errors.Is(err, app.ErrNoTeamFile):
		return "This project has no envrune.team.json. Create it with `envrune team init <your-name>`."
	case errors.Is(err, team.ErrNotRecipient):
		return "You are not a member of envrune.team.json. Send `envrune team whoami` to a member so they can add you."
	case errors.Is(err, team.ErrNotTeamRef):
		return `Team references must start with "team.", such as team.stripe.test-key.`
	case errors.Is(err, team.ErrInvalidKey):
		return "Invalid team key. Public keys start with envrune-pub- and names use letters, digits, - _ . @."
	case errors.Is(err, team.ErrDuplicateMember):
		return "A team member already has that name or key."
	case errors.Is(err, team.ErrUnknownMember):
		return "No team member has that name. See `envrune team members`."
	case errors.Is(err, team.ErrLastMember):
		return "The team file needs at least one member."
	case errors.Is(err, team.ErrUnknownRef):
		return "envrune.team.json has no such reference."
	case errors.Is(err, team.ErrInvalidFile):
		return "envrune.team.json is damaged or was edited by hand."
	case errors.Is(err, vault.ErrUnknownReference):
		return "That secret reference does not exist. See `envrune list`."
	case errors.Is(err, vault.ErrNoHistory):
		return "That secret has no earlier value to roll back to."
	case errors.Is(err, vault.ErrNoRecovery):
		return "This vault has no recovery key."
	case errors.Is(err, vault.ErrInvalidRecoveryKey):
		return "That is not a recovery key. It has 13 groups of letters and digits, such as ABCD-EFGH-...."
	case errors.Is(err, vault.ErrTooLarge):
		return "The vault would exceed 16 MiB."
	case errors.Is(err, clipboard.ErrUnavailable):
		return "No clipboard is available. On Linux, install wl-clipboard, xclip, or xsel."
	case errors.Is(err, keychain.ErrUnavailable):
		return "No system keychain is available. On Linux, install libsecret-tools (secret-tool) and run a Secret Service such as GNOME Keyring."
	case errors.Is(err, keychain.ErrNotFound):
		return "The system keychain has no EnvRune key. Run `envrune keychain enable`."
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
