package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

func revealFixture(answers ...string) (keyReveal, *int) {
	restored := 0
	return keyReveal{
		Screen: func(io.Writer) (func(), bool) { return func() { restored++ }, true },
		ReadLine: func() (string, error) {
			if len(answers) == 0 {
				return "", errors.New("end of input")
			}
			answer := answers[0]
			answers = answers[1:]
			return answer, nil
		},
		Group: func(int) int { return 2 },
	}, &restored
}

func TestARecoveryKeyLeavesTheScreenOnceItIsTypedBack(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	formatted := vault.FormatRecoveryKey(key)
	third := strings.Split(formatted, "-")[2]
	var screen, messages bytes.Buffer
	reveal, restored := revealFixture("nope", " "+strings.ToLower(third)+" ")

	reveal.show(&screen, NewPresenter(&messages, &messages, nil), key, vaultRecoveryUse, vaultRecoveryAgain)

	out := screen.String()
	enter, leave := strings.Index(out, enterAlternateScreen), strings.Index(out, leaveAlternateScreen)
	if enter != 0 || leave < 0 || strings.Index(out, formatted) < enter || strings.LastIndex(out, formatted) > leave {
		t.Fatalf("the key is not shown only on the alternate screen: %q", out)
	}
	if !strings.Contains(out, "Type group 3 of the key") || !strings.Contains(out, "That is not group 3.") {
		t.Fatalf("the screen did not ask for the group again after a wrong one: %q", out)
	}
	if *restored != 1 {
		t.Fatalf("the terminal was restored %d times", *restored)
	}
	if said := messages.String(); !strings.Contains(said, "written down, and no longer on this screen") || strings.Contains(said, formatted) {
		t.Fatalf("after the screen: %q", said)
	}
}

func TestAnUnconfirmedRecoveryKeySaysHowToGetANewOne(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	var screen, messages bytes.Buffer
	reveal, restored := revealFixture("wrong")

	reveal.show(&screen, NewPresenter(&messages, &messages, nil), key, cloudRecoveryUse, cloudRecoveryAgain)

	if !strings.HasSuffix(screen.String(), leaveAlternateScreen) || *restored != 1 {
		t.Fatalf("input ended and the alternate screen stayed: %q", screen.String())
	}
	if said := messages.String(); !strings.Contains(said, "was not confirmed") || !strings.Contains(said, "`envrune cloud recovery reset`") {
		t.Fatalf("after the screen: %q", said)
	}
}

func TestARedirectedRecoveryKeyIsPlainText(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	var out, messages bytes.Buffer

	showRecoveryKey(&out, NewPresenter(&messages, &messages, nil), key, vaultRecoveryUse, vaultRecoveryAgain)

	if got := out.String(); got != "\n    "+vault.FormatRecoveryKey(key)+"\n\n" {
		t.Fatalf("a script gets %q", got)
	}
	if said := messages.String(); !strings.Contains(said, "Write down this recovery key") || !strings.Contains(said, "envrune recover") {
		t.Fatalf("messages: %q", said)
	}
}
