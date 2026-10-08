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

func emailChangeCodeMail(to, code string, ttl time.Duration) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Confirma tu nuevo correo de Apunte",
		Text: fmt.Sprintf("Tu código para confirmar este correo es %s.\n\nCaduca en %d minutos. Si no lo pediste, ignora este correo.",
			code, int(ttl.Minutes())),
	}
}

func emailTakenMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Alguien intentó usar tu correo en Apunte",
		Text:    "Alguien intentó cambiar el correo de una cuenta de Apunte por este, que ya pertenece a otra cuenta. Si no fuiste tú, no tienes que hacer nada.",
	}
}

func emailChangedMail(to, newEmail string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "El correo de tu cuenta de Apunte cambió",
		Text: fmt.Sprintf("El correo de tu cuenta de Apunte cambió a %s. Desde ahora iniciarás sesión con ese correo.\n\n"+
			"Si no fuiste tú, contacta con soporte de inmediato.", newEmail),
	}
}
