package crawler

import "testing"

func TestExtractLinksAndFormsBuildsFormAsset(t *testing.T) {
	html := []byte(`
		<html>
			<body>
				<a href="/search?q=test">Search</a>
				<form method="post" action="/login">
					<input name="username">
					<input name="password" type="password">
					<input name="csrf" value="token">
				</form>
			</body>
		</html>`)

	links, params, forms := extractLinksAndForms(html, "https://example.com/")
	if len(links) == 0 {
		t.Fatal("expected links to be extracted")
	}
	if len(forms) != 1 {
		t.Fatalf("expected one form asset, got %d", len(forms))
	}
	form := forms[0]
	if form.Method != "POST" {
		t.Fatalf("expected POST form, got %s", form.Method)
	}
	if form.URL != "https://example.com/login" {
		t.Fatalf("unexpected form action: %s", form.URL)
	}
	if len(form.Params) != 3 || len(params) != 3 {
		t.Fatalf("expected three form params, got asset=%d aggregate=%d", len(form.Params), len(params))
	}
	if form.BodyTemplate["username"] != "" || form.BodyTemplate["password"] != "" {
		t.Fatal("expected body template fields")
	}
}
