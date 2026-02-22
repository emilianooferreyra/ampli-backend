package mail

import (
	"fmt"
	"net/smtp"
	"strings"

	"ampli/api/internal/config"
)

// Mailer handles transactional emails via SMTP (Mailtrap in dev, production SMTP in prod).
type Mailer struct {
	host string
	port string
	user string
	pass string
	from string
}

func New(cfg *config.Config) *Mailer {
	return &Mailer{
		host: cfg.SMTPHost,
		port: cfg.SMTPPort,
		user: cfg.SMTPUser,
		pass: cfg.SMTPPass,
		from: cfg.VerificationEmail,
	}
}

// SendVerificationEmail sends an OTP email to new users.
func (m *Mailer) SendVerificationEmail(to, name, token, userID string) error {
	subject := "Welcome to Ampli - Verify your email"
	body := fmt.Sprintf(`
Hello %s,

Welcome to Ampli! Please verify your email using the token below:

Token: %s

Or click this link:
%s/auth/verify-email?token=%s&userId=%s

This token expires in 1 hour.

— The Ampli Team
`, name, token, "http://localhost:8989", token, userID)

	return m.send(to, subject, body)
}

// SendForgetPasswordLink sends a password reset link.
func (m *Mailer) SendForgetPasswordLink(to, resetLink string) error {
	subject := "Ampli - Reset your password"
	body := fmt.Sprintf(`
Hello,

We received a request to reset your Ampli password.
Click the link below to reset it (valid for 1 hour):

%s

If you did not request this, please ignore this email.

— The Ampli Team
`, resetLink)

	return m.send(to, subject, body)
}

// SendPasswordResetSuccess notifies the user their password was changed.
func (m *Mailer) SendPasswordResetSuccess(to, name string) error {
	subject := "Ampli - Password reset successfully"
	body := fmt.Sprintf(`
Hello %s,

Your Ampli password has been reset successfully.

If you did not make this change, please contact our support immediately.

— The Ampli Team
`, name)

	return m.send(to, subject, body)
}

func (m *Mailer) send(to, subject, body string) error {
	addr := m.host + ":" + m.port
	auth := smtp.PlainAuth("", m.user, m.pass, m.host)

	msg := strings.Join([]string{
		"From: " + m.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	return smtp.SendMail(addr, auth, m.from, []string{to}, []byte(msg))
}
