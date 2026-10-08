package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/mailer"
)

func resetMail(to, webBase, token string, ttl time.Duration) mailer.Message {
	link := strings.TrimRight(webBase, "/") + "/reset-password?token=" + token
	return mailer.Message{
		To:      to,
		Subject: "Restablece tu contraseña de Apunte",
		Text: fmt.Sprintf("Para crear una contraseña nueva abre este enlace (caduca en %d minutos y solo sirve una vez):\n\n%s\n\n"+
			"Si no lo pediste, ignora este correo: tu contraseña no cambia.\n\n"+
			"Recuerda: para conservar tus notas necesitarás tu clave de recuperación. Sin ella, solo podrás empezar de cero.",
			int(ttl.Minutes()), link),
	}
}

func passwordChangedMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Tu contraseña de Apunte cambió",
		Text: "La contraseña de tu cuenta de Apunte se cambió y se cerraron las sesiones en tus otros dispositivos.\n\n" +
			"Si no fuiste tú, restablécela desde «Olvidé mi contraseña» cuanto antes.",
	}
}

func accountDeletedMail(to string, days int) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Tu cuenta de Apunte se eliminará",
		Text: fmt.Sprintf("Programamos la eliminación de tu cuenta de Apunte. Tus datos se borrarán de forma definitiva en %d días.\n\n"+
			"Si no fuiste tú, usa «Olvidé mi contraseña» antes de ese plazo: al restablecer la contraseña la cuenta se recupera.", days),
	}
}
