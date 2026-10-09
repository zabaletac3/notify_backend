package auth

import (
	"fmt"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
)

func verificationMail(to, code string, ttl time.Duration) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Tu código de verificación de AxoNote",
		Text: fmt.Sprintf("Tu código de verificación es %s.\n\nCaduca en %d minutos. Si no creaste una cuenta en AxoNote, ignora este correo.",
			code, int(ttl.Minutes())),
	}
}

func existingAccountMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Alguien intentó registrar tu correo en AxoNote",
		Text: "Alguien intentó crear una cuenta en AxoNote con este correo, que ya tiene una.\n\n" +
			"Si fuiste tú, inicia sesión o usa «Olvidé mi contraseña». Si no, no tienes que hacer nada: tu cuenta sigue intacta.",
	}
}
