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
		Subject: "Restablece tu contraseña de AxoNote",
		Text: fmt.Sprintf("Para crear una contraseña nueva abre este enlace (caduca en %d minutos y solo sirve una vez):\n\n%s\n\n"+
			"Si no lo pediste, ignora este correo: tu contraseña no cambia.\n\n"+
			"Recuerda: para conservar tus notas necesitarás tu clave de recuperación. Sin ella, solo podrás empezar de cero.",
			int(ttl.Minutes()), link),
	}
}

func passwordChangedMail(to string) mailer.Message {
	return passwordChangedMailMFA(to, false)
}

// passwordChangedMailMFA avisa del cambio de contraseña y, si procede, de que además se desactivó la
// verificación en dos pasos (S3/M5).
func passwordChangedMailMFA(to string, mfaDisabled bool) mailer.Message {
	text := "La contraseña de tu cuenta de AxoNote se cambió y se cerraron las sesiones en tus otros dispositivos.\n\n" +
		"Si no fuiste tú, restablécela desde «Olvidé mi contraseña» cuanto antes."
	if mfaDisabled {
		text += "\n\nAdemás, se desactivó la verificación en dos pasos de tu cuenta."
	}
	return mailer.Message{To: to, Subject: "Tu contraseña de AxoNote cambió", Text: text}
}

func mfaEnabledMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Activaste la verificación en dos pasos de AxoNote",
		Text: "La verificación en dos pasos ya está activa en tu cuenta de AxoNote. Desde ahora, para abrir una sesión nueva " +
			"necesitarás tu contraseña y un código de tu aplicación de autenticación.\n\n" +
			"Guarda los códigos de respaldo en un lugar seguro: son la única forma de entrar si pierdes el autenticador.\n\n" +
			"Si no fuiste tú, cambia tu contraseña cuanto antes.",
	}
}

func mfaDisabledMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Desactivaste la verificación en dos pasos de AxoNote",
		Text: "La verificación en dos pasos ya no está activa en tu cuenta de AxoNote. Para abrir una sesión nueva bastará " +
			"tu contraseña.\n\nSi no fuiste tú, cambia tu contraseña y vuelve a activarla cuanto antes.",
	}
}

func googleLinkedMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Vinculaste Google con tu cuenta de AxoNote",
		Text: "Ya puedes iniciar sesión en AxoNote con Google. Tu contraseña de AxoNote sigue siendo necesaria para " +
			"descifrar tus notas en los dispositivos nuevos.\n\nSi no fuiste tú, cambia tu contraseña y desvincula Google cuanto antes.",
	}
}

func googleUnlinkedMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Desvinculaste Google de tu cuenta de AxoNote",
		Text: "Google ya no está vinculado con tu cuenta de AxoNote. Para entrar tendrás que usar tu correo y tu " +
			"contraseña, como antes.\n\nSi no fuiste tú, cambia tu contraseña cuanto antes.",
	}
}

func accountDeletedMail(to string, days int) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Tu cuenta de AxoNote se eliminará",
		Text: fmt.Sprintf("Programamos la eliminación de tu cuenta de AxoNote. Tus datos se borrarán de forma definitiva en %d días.\n\n"+
			"Si no fuiste tú, usa «Olvidé mi contraseña» antes de ese plazo: al restablecer la contraseña la cuenta se recupera.", days),
	}
}

func emailChangeCodeMail(to, code string, ttl time.Duration) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Confirma tu nuevo correo de AxoNote",
		Text: fmt.Sprintf("Tu código para confirmar este correo es %s.\n\nCaduca en %d minutos. Si no lo pediste, ignora este correo.",
			code, int(ttl.Minutes())),
	}
}

func emailTakenMail(to string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "Alguien intentó usar tu correo en AxoNote",
		Text:    "Alguien intentó cambiar el correo de una cuenta de AxoNote por este, que ya pertenece a otra cuenta. Si no fuiste tú, no tienes que hacer nada.",
	}
}

func emailChangedMail(to, newEmail string) mailer.Message {
	return mailer.Message{
		To:      to,
		Subject: "El correo de tu cuenta de AxoNote cambió",
		Text: fmt.Sprintf("El correo de tu cuenta de AxoNote cambió a %s. Desde ahora iniciarás sesión con ese correo.\n\n"+
			"Si no fuiste tú, contacta con soporte de inmediato.", newEmail),
	}
}
