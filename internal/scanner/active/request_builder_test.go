package active

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
)

func TestBuildProbeRequestReplacesQueryValueWithoutAppending(t *testing.T) {
	asset := &models.Asset{Method: http.MethodGet, URL: "https://example.test/search?q=old&keep=1"}
	entry := models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "q", Location: models.EntryPointQuery}

	req, err := BuildProbeRequest(asset, entry, "' OR '1'='1")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodGet || req.URL.Query().Get("q") != "' OR '1'='1" || req.URL.Query().Get("keep") != "1" {
		t.Fatalf("query value was not replaced precisely: %s", req.URL.String())
	}
}

func TestBuildProbeRequestSupportsNestedJSONArraysAndGraphQLVariables(t *testing.T) {
	asset := &models.Asset{
		Method:   http.MethodPost,
		URL:      "https://example.test/api",
		BodyType: "json",
		BodyRaw:  `{"filters":{"items":[{"url":"original","name":"stable"}]},"page":1}`,
	}
	entry := models.EntryPoint{Endpoint: asset.URL, Method: http.MethodPost, Name: "filters.items[0].url", Location: models.EntryPointJSON}
	req, err := BuildProbeRequest(asset, entry, "https://probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	items := document["filters"].(map[string]any)["items"].([]any)
	if items[0].(map[string]any)["url"] != "https://probe.invalid" || document["page"] != float64(1) {
		t.Fatalf("nested JSON value was not replaced: %s", body)
	}

	graphql := &models.Asset{
		Method:   http.MethodPost,
		URL:      "https://example.test/graphql",
		BodyType: "graphql",
		BodyRaw:  `{"query":"query($url:String!){fetch(url:$url)}","variables":{"url":"original","limit":5}}`,
	}
	graphqlEntry := models.EntryPoint{Endpoint: graphql.URL, Method: http.MethodPost, Name: "variables.url", Location: models.EntryPointGraphQL}
	graphqlReq, err := BuildProbeRequest(graphql, graphqlEntry, "callback")
	if err != nil {
		t.Fatal(err)
	}
	graphqlBody, _ := io.ReadAll(graphqlReq.Body)
	var graphqlDocument map[string]any
	if err := json.Unmarshal(graphqlBody, &graphqlDocument); err != nil {
		t.Fatal(err)
	}
	if graphqlDocument["variables"].(map[string]any)["url"] != "callback" {
		t.Fatalf("GraphQL variable was not replaced: %s", graphqlBody)
	}
}

func TestBuildProbeRequestSupportsFormXMLMultipartPathHeaderAndCookie(t *testing.T) {
	formAsset := &models.Asset{Method: http.MethodPost, URL: "https://example.test/form", BodyType: "form-urlencoded", BodyRaw: "keep=1&target=old"}
	formReq, err := BuildProbeRequest(formAsset, models.EntryPoint{Endpoint: formAsset.URL, Method: http.MethodPost, Name: "target", Location: models.EntryPointForm}, "probe")
	if err != nil {
		t.Fatal(err)
	}
	formValues, _ := url.ParseQuery(readBody(t, formReq))
	if formValues.Get("target") != "probe" || formValues.Get("keep") != "1" {
		t.Fatalf("form value was not replaced: %v", formValues)
	}

	xmlAsset := &models.Asset{Method: http.MethodPost, URL: "https://example.test/xml", BodyType: "xml", BodyRaw: `<root><target>old</target><item id="old-id">stable</item></root>`}
	xmlReq, err := BuildProbeRequest(xmlAsset, models.EntryPoint{Endpoint: xmlAsset.URL, Method: http.MethodPost, Name: "root.target", Location: models.EntryPointXML}, "probe&value")
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, xmlReq); !strings.Contains(body, "<target>probe&amp;value</target>") {
		t.Fatalf("XML element was not replaced safely: %s", body)
	}

	multipartAsset := &models.Asset{Method: http.MethodPost, URL: "https://example.test/upload", BodyType: "multipart", BodyTemplate: map[string]string{"file": "fixture", "name": "old"}}
	multipartReq, err := BuildProbeRequest(multipartAsset, models.EntryPoint{Endpoint: multipartAsset.URL, Method: http.MethodPost, Name: "name", Location: models.EntryPointMultipart}, "probe")
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(multipartReq.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("invalid multipart content type: %s", multipartReq.Header.Get("Content-Type"))
	}
	reader := multipart.NewReader(multipartReq.Body, params["boundary"])
	fields := map[string]string{}
	for {
		part, readErr := reader.NextPart()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		content, _ := io.ReadAll(part)
		fields[part.FormName()] = string(content)
	}
	if fields["name"] != "probe" || fields["file"] != "fixture" {
		t.Fatalf("multipart field was not replaced: %#v", fields)
	}

	pathAsset := &models.Asset{Method: http.MethodGet, URL: "https://example.test/users/42/profile", Headers: map[string]string{"X-Trace": "stable"}, Cookies: map[string]string{"session": "old"}}
	pathReq, err := BuildProbeRequest(pathAsset, models.EntryPoint{Endpoint: pathAsset.URL, Method: http.MethodGet, Name: "path[1]", Location: models.EntryPointPath}, "43")
	if err != nil {
		t.Fatal(err)
	}
	if pathReq.URL.Path != "/users/43/profile" {
		t.Fatalf("path segment was not replaced: %s", pathReq.URL.Path)
	}

	headerReq, err := BuildProbeRequest(pathAsset, models.EntryPoint{Endpoint: pathAsset.URL, Method: http.MethodGet, Name: "X-Trace", Location: models.EntryPointHeader}, "probe-header")
	if err != nil {
		t.Fatal(err)
	}
	if headerReq.Header.Get("X-Trace") != "probe-header" || headerReq.Header.Get("Cookie") != "session=old" {
		t.Fatalf("header/cookie context was not preserved: headers=%v", headerReq.Header)
	}
	cookieReq, err := BuildProbeRequest(pathAsset, models.EntryPoint{Endpoint: pathAsset.URL, Method: http.MethodGet, Name: "session", Location: models.EntryPointCookie}, "probe-cookie")
	if err != nil {
		t.Fatal(err)
	}
	if cookieReq.Cookies()[0].Value != "probe-cookie" {
		t.Fatalf("cookie value was not replaced: %v", cookieReq.Cookies())
	}
}

func TestPlansForModuleDiscoverNestedJSONAndXMLEntryPoints(t *testing.T) {
	jsonAsset := &models.Asset{Method: http.MethodPost, URL: "https://example.test/api", BodyType: "json", BodyRaw: `{"filters":{"url":"original","name":"stable"}}`}
	plans := PlansForModule("ssrf-basic", &models.ModuleContext{Asset: jsonAsset}, nil)
	if len(plans) != 1 || plans[0].EntryPoint.Name != "filters.url" || plans[0].EntryPoint.Location != models.EntryPointJSON {
		t.Fatalf("nested JSON entry point was not discovered: %+v", plans)
	}

	xmlAsset := &models.Asset{Method: http.MethodPost, URL: "https://example.test/import", BodyType: "xml", BodyRaw: `<request><source>original</source></request>`}
	plans = PlansForModule("ssrf-basic", &models.ModuleContext{Asset: xmlAsset}, nil)
	if len(plans) != 1 || plans[0].EntryPoint.Name != "request.source" || plans[0].EntryPoint.Location != models.EntryPointXML {
		t.Fatalf("XML entry point was not discovered: %+v", plans)
	}
}

func readBody(t *testing.T, request *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
