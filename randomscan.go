package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

var (
	headers     customheaders
	paramFile   string
	paramCount  int
	proxy       string
	onlyPOC     bool
	paramList   []string
	concurrency int
	htmlOnly    bool // ainda útil para filtrar outputs gerais se desejar
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to use")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output")
	flag.BoolVar(&htmlOnly, "html", false, "Only print matches if response is HTML (applies mainly to XSS/Link tests)")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads (min 15)")
	flag.Usage = usage
}

func usage() {
	fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___|

Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject (random sample)
  -proxy    Proxy address
  -H        Headers (repeatable)
  -s        Show only PoC (hide "Not Vulnerable")
  -html     Only print XSS/Link results if Content-Type is text/html
  -t        Number of threads (default 50, minimum 15)
`)
}

func main() {
	flag.Parse()
	if concurrency < 15 {
		concurrency = 15
	}

	if paramFile != "" {
		params, err := readParamFile(paramFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read param file:", err)
			os.Exit(1)
		}
		paramList = params
	}

	stdin := bufio.NewScanner(os.Stdin)
	targets := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				results := runAllTests(target)
				for _, res := range results {
					if res != "" {
						fmt.Println(res)
					}
				}
			}
		}()
	}

	visited := make(map[string]bool)
	for stdin.Scan() {
		u := strings.TrimSpace(stdin.Text())
		if u == "" {
			continue
		}
		if !visited[u] {
			targets <- u
			visited[u] = true
		}
	}

	close(targets)
	wg.Wait()
}

func readParamFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var params []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			params = append(params, line)
		}
	}
	return params, sc.Err()
}

func getRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 {
		return nil
	}
	if count >= len(params) {
		return params
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

type TestCase struct {
	Name        string
	Payloads    []string
	NeedHTML    bool
	Detector    func(method, urlStr string, resp *http.Response, body []byte) (bool, string)
	Description string
}

func runAllTests(base string) []string {
	if len(paramList) == 0 || paramCount <= 0 {
		return []string{"[!] Skipped (no params or count)"}
	}

	selectedParams := getRandomParams(paramList, paramCount)
	client := buildClient()

	tests := []TestCase{
		{
			Name:     "XSS",
			Payloads: []string{`%27%22teste`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if contains(body, `'"teste`) {
					return true, `match: '"teste`
				}
				return false, ""
			},
		},
		{
			Name:     "XSS Script",
			Payloads: []string{`%3C%2Fscript%3E%3Cteste%3E`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if contains(body, `</script><teste>`) {
					return true, "match: </script><teste>"
				}
				return false, ""
			},
		},
		{
			Name:     "CRLF Injection",
			Payloads: []string{`%0d%0aset-cookie:efx`, `%0d%0a%0d%0aset-cookie:efx`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte) (bool, string) {
				// Case-insensitive check for a header that looks like Set-Cookie injected with value containing efx
				for k, vals := range resp.Header {
					if strings.EqualFold(k, "Set-Cookie") || strings.Contains(strings.ToLower(k), "set-cookie") {
						for _, v := range vals {
							if strings.Contains(strings.ToLower(v), "efx") {
								return true, fmt.Sprintf("header: %s: %s", k, v)
							}
						}
					}
				}
				return false, ""
			},
		},
		{
			Name:     "Redirect/SSRF",
			Payloads: []string{`https://example.com`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte) (bool, string) {
				// If client followed redirect or target fetched remote content, body will include Example Domain
				if contains(body, "Example Domain") {
					return true, "match: Example Domain"
				}
				return false, ""
			},
		},
		{
			Name:     "Link Manipulation",
			Payloads: []string{`https://efxtech.com`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				low := strings.ToLower(string(body))
				if strings.Contains(low, `href="https://efxtech.com`) ||
					strings.Contains(low, `src="https://efxtech.com`) ||
					strings.Contains(low, `action="https://efxtech.com`) {
					return true, `match: href/src/action="https://efxtech.com`
				}
				return false, ""
			},
		},
	}

	var results []string
	for _, tc := range tests {
		for _, payload := range tc.Payloads {
			// GET
			getURL, ok := addParamsRaw(base, selectedParams, payload)
			if ok {
				req, err := http.NewRequest("GET", getURL, nil)
				if err == nil {
					applyHeaders(req)
					if resp, err := client.Do(req); err == nil {
						body, _ := readAllLimit(resp.Body, 2<<20) // 2MB
						resp.Body.Close()
						if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
							if vul, detail := tc.Detector("GET", getURL, resp, body); vul {
								results = append(results, formatVuln(tc.Name, "GET", getURL, detail))
							} else if !onlyPOC {
								results = append(results, formatNotVuln(tc.Name, "GET", getURL))
							}
						}
					}
				}
			}

			// POST (application/x-www-form-urlencoded) — raw pairs to avoid double-encode
			postURL := base
			bodyStr := buildFormBodyRaw(selectedParams, payload)
			req, err := http.NewRequest("POST", postURL, strings.NewReader(bodyStr))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				applyHeaders(req)
				if resp, err := client.Do(req); err == nil {
					body, _ := readAllLimit(resp.Body, 2<<20)
					resp.Body.Close()
					if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
						if vul, detail := tc.Detector("POST", postURL, resp, body); vul {
							results = append(results, formatVuln(tc.Name, "POST", postURL, detail+" [body:"+bodyStr+"]"))
						} else if !onlyPOC {
							results = append(results, formatNotVuln(tc.Name, "POST", postURL+" [body:"+bodyStr+"]"))
						}
					}
				}
			}
		}
	}

	return results
}

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		Proxy:           nil,
	}
	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
		// CheckRedirect default segue redirecionamentos (bom p/ Redirect/SSRF)
	}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func addParamsRaw(base string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	// preserva tudo até ? (mas vamos substituir a query)
	u.RawQuery = buildQueryRaw(params, rawValue)
	return u.String(), true
}

func buildQueryRaw(params []string, rawValue string) string {
	// monta p1=<raw>&p2=<raw> sem re-escapar
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p)) // nome do param pode escapar
		b.WriteByte('=')
		b.WriteString(rawValue) // valor já vem "pré-encodado" pelo payload fornecido
	}
	return b.String()
}

func buildFormBodyRaw(params []string, rawValue string) string {
	// mesma ideia do query
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p))
		b.WriteByte('=')
		b.WriteString(rawValue)
	}
	return b.String()
}

func isHTML(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func contains(body []byte, s string) bool {
	return strings.Contains(string(body), s)
}

func readAllLimit(r io.ReadCloser, max int64) ([]byte, error) {
	// leitura simples com limite
	type limitedReader interface {
		Read([]byte) (int, error)
	}
	return io.ReadAll(io.LimitReader(r, max))
}

// Helpers de formatação
var stripANSIRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
	if onlyPOC {
		// modo PoC: imprime só a URL e o tipo
		return fmt.Sprintf("%s | %s", urlStr, kind)
	}
	return msg
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}
