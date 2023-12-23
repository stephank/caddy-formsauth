package formsauth

import (
	_ "embed"
	"log"

	"html/template"
)

//go:embed tmpl.html
var loginHtml string
var loginTemplate *template.Template

// LoginContext is the view-model for the login form template.
type LoginContext struct {
	LoginRoute string
	ReturnTo   string
}

// initTemplate preparess the login form template.
func initTemplate() {
	tmpl, err := template.New("formsLogin").Parse(loginHtml)
	if err != nil {
		log.Fatalf("Template.Parse(): %v", err)
	}
	loginTemplate = tmpl
}
