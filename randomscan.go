package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

// -------------------- Flags e tipos --------------------

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
	htmlOnly    bool
	scanOpt     string
	scanFilter  map[int]bool
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to inject (random sample)")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL (HTTP proxy supported for raw CRLF read)")
	flag.StringVar(&proxy, "x", "", "Proxy URL (HTTP proxy supported for raw CRLF read)")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output (suppress Not Vulnerable)")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output (suppress Not Vulnerable)")
	flag.BoolVar(&htmlOnly, "html", false, "Only print XSS/Link results if Content-Type is text/html")
	flag.Var(&headers, "H", "Add header (repeatable)")
	flag.Var(&headers, "headers", "Add header (repeatable)")
	flag.IntVar(&concurrency, "t", 50, "Number of threads (default 50, minimum 15)")

	flag.StringVar(&scanOpt, "o", "", "Scan options (e.g. -o 1,2)\n"+
		"   1 = XSS (inclui XSS Script)\n"+
		"   2 = CRLF Injection\n"+
		"   3 = Redirect/SSRF\n"+
		"   4 = Link Manipulation\n"+
		"   5 = SSTI")

	flag.Usage = func() {
		fmt.Println(`
Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject (random sample)
  -proxy    Proxy address (HTTP proxy supported in raw CRLF check)
  -H        Headers (repeatable)
  -s        Show only PoC (hide "Not Vulnerable")
  -html     Only print XSS/Link results if Content-Type is text/html
  -t        Number of threads (default 50, minimum 15)
  -o        Scan options (e.g. -o 1,2)
            1 = XSS (inclui XSS Script)
            2 = CRLF Injection
            3 = Redirect/SSRF
            4 = Link Manipulation
            5 = SSTI
`)
	}
}

// -------------------- Main --------------------

func main() {
	flag.Parse()
	if concurrency < 15 {
		concurrency = 15
	}
	scanFilter = parseScanOptions(scanOpt)

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

// -------------------- Utilidades --------------------

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
	rand.Shuffle(len(params), func(i, j int) {
		r[i], r[j] = r[j], r[i]
	})
	return r[:count]
}

// -------------------- HTTP Headers e Client --------------------

func defaultHeaderMap() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64)",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8",
		"Accept-Encoding": "gzip, deflate, br",
		"Connection":      "close",
	}
}

func userHeaderMap(h customheaders) map[string]string {
	m := make(map[string]string)
	for _, raw := range h {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func mergeHeaders(base, override map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
		DialContext:        (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
	}
	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

func applyHeaders(req *http.Request) {
	h := mergeHeaders(defaultHeaderMap(), userHeaderMap(headers))
	for k, v := range h {
		req.Header.Set(k, v)
	}
}

// -------------------- Param Builders --------------------

func addParamsRaw(base string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	u.RawQuery = buildQueryRaw(params, rawValue)
	return u.String(), true
}

func buildQueryRaw(params []string, rawValue string) string {
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

func buildFormBodyRaw(params []string, rawValue string) string {
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

// -------------------- Test Cases --------------------

type TestCase struct {
	ID       int
	Name     string
	Payloads []string
	NeedHTML bool
	Detector func(string, string, *http.Response, []byte, string) (bool, string)
}

func runAllTests(base string) []string {
	if len(paramList) == 0 || paramCount <= 0 {
		return []string{"[!] Skipped (no params or count)"}
	}
	selectedParams := getRandomParams(paramList, paramCount)
	client := buildClient()

	tests := []TestCase{
		{
			ID:       1,
			Name:     "XSS",
			Payloads: []string{`%27%22teste`, `%3f%26%27%22teste`},
			NeedHTML: true,
			Detector: func(_, _ string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if strings.Contains(string(body), `'"teste`) {
					return true, `match: '"teste`
				}
				return false, ""
			},
		},
		{
			ID:       1,
			Name:     "XSS Script",
			Payloads: []string{`%3C%2Fscript%3E%3Cteste%3E`},
			NeedHTML: true,
			Detector: func(_, _ string, resp *http.Response, body []byte, _ string) (bool, string) {
				if isHTML(resp) && strings.Contains(string(body), "</script><teste>") {
					return true, "match: </script><teste>"
				}
				return false, ""
			},
		},
		{
			ID:       2,
			Name:     "CRLF Injection",
			Payloads: []string{`%0d%0aset-cookie:efx`, `%0d%0a%0d%0aset-cookie:efx`},
			Detector: func(m, u string, _ *http.Response, _ []byte, body string) (bool, string) {
				rawHead, err := fetchRawResponseHead(m, u, body, headers, proxy)
				if err == nil && strings.Contains(strings.ToLower(rawHead), "set-cookie: efx") {
					return true, "raw-header: set-cookie: efx"
				}
				return false, ""
			},
		},
		{
			ID:       3,
			Name:     "Redirect/SSRF",
			Payloads: []string{`https://example.com`},
			Detector: func(_, _ string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "Example Domain") {
					return true, "match: Example Domain"
				}
				return false, ""
			},
		},
		{
			ID:       4,
			Name:     "Link Manipulation",
			Payloads: []string{`https://efxtech.com`},
			NeedHTML: true,
			Detector: func(_, _ string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				return linkManipulationMatch(body, "efxtech.com")
			},
		},
		{
			ID:       5,
			Name:     "SSTI",
			Payloads: []string{`{{7*7}}efxtech`, `${{7*7}}efxtech`, `*{7*7}efxtech`},
			Detector: func(_, _ string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "49efxtech") {
					return true, "match: 49efxtech"
				}
				return false, ""
			},
		},
	}

	var results []string
	for _, tc := range tests {
		if scanFilter != nil && !scanFilter[tc.ID] {
			continue
		}
		for _, payload := range tc.Payloads {
			getURL, ok := addParamsRaw(base, selectedParams, payload)
			if ok {
				req, _ := http.NewRequest("GET", getURL, nil)
				applyHeaders(req)
				resp, err := client.Do(req)
				if err == nil {
					body, _ := readBodyDecodedLimit(resp, 2<<20)
					resp.Body.Close()
					if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || isHTML(resp)) {
						if vul, det := tc.Detector("GET", getURL, resp, body, ""); vul {
							results = append(results, formatVuln(tc.Name, "GET", getURL, det))
						} else if !onlyPOC {
							results = append(results, formatNotVuln(tc.Name, "GET", getURL))
						}
					}
				}
			}
			bodyStr := buildFormBodyRaw(selectedParams, payload)
			req, _ := http.NewRequest("POST", base, strings.NewReader(bodyStr))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			applyHeaders(req)
			resp, err := client.Do(req)
			if err == nil {
				body, _ := readBodyDecodedLimit(resp, 2<<20)
				resp.Body.Close()
				if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || isHTML(resp)) {
					if vul, det := tc.Detector("POST", base, resp, body, bodyStr); vul {
						results = append(results, formatVuln(tc.Name, "POST", base, det))
					} else if !onlyPOC {
						results = append(results, formatNotVuln(tc.Name, "POST", base))
					}
				}
			}
		}
	}
	return results
}

// -------------------- Link Manipulation Helper --------------------

func linkManipulationMatch(body []byte, domain string) (bool, string) {
	low := strings.ToLower(string(body))
	dom := regexp.QuoteMeta(domain)
	patterns := []string{
		`(?:src|srcdoc|action|href)\s*=\s*["']?(?:https?:\/\/|\/\/)?` + dom,
		`html\s*(?:=|\(|:)\s*["']?(?:https?:\/\/|\/\/)?` + dom,
		`['"]href['"]\s*,\s*['"]?(?:https?:\/\/|\/\/)?` + dom,
		`(?:assign|replace|reload|eval|settimeout|write|fetch|location|add|append|url)\s*\(\s*['"]?(?:https?:\/\/|\/\/)?` + dom,
		`(?:hash|url|location)\s*=\s*['"]?(?:https?:\/\/|\/\/)?` + dom,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if loc := re.FindStringIndex(low); loc != nil {
			ctx := low[max(0, loc[0]-40):min(len(low), loc[1]+40)]
			return true, fmt.Sprintf("match: %s", strings.TrimSpace(ctx))
		}
	}
	return false, ""
}

func min(a, b int) int { if a < b { return a }; return b }
func max(a, b int) int { if a > b { return a }; return b }

// -------------------- HTTP util --------------------

func isHTML(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

func readBodyDecodedLimit(resp *http.Response, max int64) ([]byte, error) {
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	var r io.Reader = io.LimitReader(resp.Body, max)
	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(r)
		if err != nil {
			return io.ReadAll(r)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "deflate":
		fr := flate.NewReader(r)
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return io.ReadAll(r)
	}
}

// -------------------- Formatação --------------------

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s | %s", kind, method, urlStr, detail)
	if onlyPOC {
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

func parseScanOptions(opt string) map[int]bool {
	if strings.TrimSpace(opt) == "" {
		return nil
	}
	m := make(map[int]bool)
	for _, p := range strings.Split(opt, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
			m[n] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// -------------------- CRLF Raw Fetch --------------------

func fetchRawResponseHead(method, fullURL, body string, addHeaders customheaders, proxyURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", host, 6*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, u.RequestURI(), u.Host)
	conn.Write([]byte(reqLine))
	buf := bufio.NewReader(conn)
	head, _ := buf.ReadString('\n')
	return head, nil
}
