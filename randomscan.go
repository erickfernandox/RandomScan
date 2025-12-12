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

// -------------------- Tipos e flags --------------------

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

// ANSI colors
const (
	colorRed   = "\x1b[31m"
	colorReset = "\x1b[0m"
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
		"   3 = Redirect/SSRF + Open Redirect\n"+
		"   4 = Link Manipulation\n"+
		"   5 = SSTI\n"+
		"   6 = Path Traversal")

	flag.Usage = func() {
		fmt.Println(`
Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject (random sample, clusterbomb)
  -proxy    Proxy address (HTTP proxy supported in raw CRLF check)
  -H        Headers (repeatable)
  -s        Show only PoC (hide "Not Vulnerable")
  -html     Only print XSS/Link results if Content-Type is text/html
  -t        Number of threads (default 50, minimum 15)
  -o        Scan options (e.g. -o 1,2,3)
            1 = XSS (inclui XSS Script)
            2 = CRLF Injection
            3 = Redirect/SSRF + Open Redirect
            4 = Link Manipulation
            5 = SSTI
            6 = Path Traversal
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
			visited[u] = true
			targets <- u
		}
	}

	close(targets)
	wg.Wait()
}

// -------------------- Arquivo / params --------------------

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
		r := make([]string, len(params))
		copy(r, params)
		return r
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

// -------------------- Headers / client --------------------

func defaultHeaderMap() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Encoding": "gzip, deflate, br",
		"Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
		"Connection":      "close",
	}
}

func userHeaderMap(h customheaders) map[string]string {
	m := make(map[string]string)
	for _, raw := range h {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k != "" {
			m[http.CanonicalHeaderKey(k)] = v
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
		DialContext:        (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		DisableCompression: true,
	}
	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}
}

func applyHeaders(req *http.Request) {
	base := defaultHeaderMap()
	user := userHeaderMap(headers)
	final := mergeHeaders(base, user)
	for k, v := range final {
		req.Header.Set(k, v)
	}
}

// -------------------- Montagem query/body --------------------

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

// GET normal com clusterbomb
func addParamsRaw(baseURL string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	u.RawQuery = buildQueryRaw(params, rawValue)
	return u.String(), true
}

// Traversal genérico: /%2e%2e%2f?<clusterbomb>
// Usado APENAS em:
//  - XSS básico (ID=1, Name=="XSS", payload %27%22teste)
//  - Open redirect (ID=3, payload https://example.com)
func addTraversalAndParamsRaw(baseURL string, params []string, rawValue string) (string, bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		// tenta baseURL sem esquema
		u2, err2 := url.Parse("http://" + baseURL)
		if err2 != nil {
			return "", false
		}
		u = u2
	}

	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := u.Host
	if host == "" {
		return "", false
	}

	query := buildQueryRaw(params, rawValue)
	path := "/%2e%2e%2f"

	if query != "" {
		return fmt.Sprintf("%s://%s%s?%s", scheme, host, path, query), true
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path), true
}

// -------------------- Test cases --------------------

type TestCase struct {
	ID       int
	Name     string
	Payloads []string
	NeedHTML bool
	Detector func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string)
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				if strings.Contains(string(body), "</script><teste>") {
					return true, "match: </script><teste>"
				}
				return false, ""
			},
		},
		{
			ID:       2,
			Name:     "CRLF Injection",
			Payloads: []string{`%0d%0aset-cookie:efx`, `%0d%0a%0d%0aset-cookie:efx`},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, _ []byte, sentBody string) (bool, string) {
				rawHead, rawErr := fetchRawResponseHead(method, urlStr, sentBody, headers, proxy)
				if rawErr == nil {
					lines := strings.Split(rawHead, "\r\n")
					for _, ln := range lines {
						l := strings.ToLower(strings.TrimSpace(ln))
						if strings.HasPrefix(l, "set-cookie: efx") {
							return true, "raw-header: " + ln
						}
					}
				}
				return false, ""
			},
		},
		{
			ID: 3,
			Name: "Redirect/SSRF + Open Redirect",
			Payloads: []string{
				`https://example.com`,
				`//example.com`,
				`/%5cexample.com`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, _ string) (bool, string) {
				if !isHTML(resp) {
					return false, ""
				}
				return linkManipulationMatch(body, "efxtech.com")
			},
		},
		{
			ID:       5,
			Name:     "SSTI",
			Payloads: []string{
				`{{7*7}}efxtech`,
				`${{7*7}}efxtech`,
				`*{7*7}efxtech`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "49efxtech") {
					return true, "match: 49efxtech"
				}
				return false, ""
			},
		},
		{
			ID: 6,
			Name: "Path Traversal",
			Payloads: []string{
				`../../../../../../etc/passwd`,
				`////../../../../../../etc/passwd`,
				`file://etc/passwd`,
				`%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, _ *http.Response, body []byte, _ string) (bool, string) {
				if strings.Contains(string(body), "root:x:") {
					return true, "match: root:x:"
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

			// -------- GET normal (clusterbomb) --------
			if getURL, ok := addParamsRaw(base, selectedParams, payload); ok {
				if res := doRequestAndDetect(client, "GET", getURL, tc, ""); res != "" {
					results = append(results, res)
				}
			}

			// -------- Traversal SOMENTE para:
			//  - XSS básico com payload %27%22teste
			if tc.ID == 1 && tc.Name == "XSS" && payload == `%27%22teste` {
				if travURL, ok := addTraversalAndParamsRaw(base, selectedParams, payload); ok {
					if res := doRequestAndDetect(client, "GET", travURL, tc, ""); res != "" {
						results = append(results, res)
					}
				}
			}
			//  - Open redirect com payload https://example.com
			if tc.ID == 3 && payload == `https://example.com` {
				if travURL, ok := addTraversalAndParamsRaw(base, selectedParams, payload); ok {
					if res := doRequestAndDetect(client, "GET", travURL, tc, ""); res != "" {
						results = append(results, res)
					}
				}
			}

			// -------- POST x-www-form-urlencoded (clusterbomb) --------
			bodyStr := buildFormBodyRaw(selectedParams, payload)
			if res := doRequestAndDetect(client, "POST", base, tc, bodyStr); res != "" {
				results = append(results, res)
			}
		}
	}

	return results
}

// -------------------- doRequestAndDetect --------------------

// extraBody: para POST, é o body enviado (aparece no output)
func doRequestAndDetect(client *http.Client, method, fullURL string, tc TestCase, extraBody string) string {
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", fullURL, strings.NewReader(extraBody))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return ""
		}
	}

	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := readBodyDecodedLimit(resp, 2<<20)
	resp.Body.Close()

	if tc.NeedHTML && !isHTML(resp) {
		return ""
	}
	if htmlOnly && tc.NeedHTML && !isHTML(resp) {
		return ""
	}

	sentBody := ""
	if method == "POST" {
		sentBody = extraBody
	}

	vul, det := tc.Detector(method, fullURL, resp, body, sentBody)

	if vul {
		if method == "POST" && sentBody != "" {
			if det != "" {
				det += " "
			}
			det += "[body:" + sentBody + "]"
		}
		return formatVuln(tc.Name, method, fullURL, det)
	}

	if !onlyPOC {
		msg := formatNotVuln(tc.Name, method, fullURL)
		if method == "POST" && sentBody != "" {
			msg += " [body:" + sentBody + "]"
		}
		return msg
	}

	return ""
}

// -------------------- CRLF raw --------------------

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

	var conn net.Conn
	dialTimeout := 6 * time.Second

	base := defaultHeaderMap()
	user := userHeaderMap(addHeaders)
	final := mergeHeaders(base, user)

	readHead := func(c net.Conn, reqTarget string, tlsWrap bool) (string, error) {
		if tlsWrap {
			serverName := u.Hostname()
			tconn := tls.Client(c, &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
			})
			if err := tconn.Handshake(); err != nil {
				return "", err
			}
			c = tconn
		}

		if reqTarget == "" {
			reqTarget = u.RequestURI()
		}
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"

		var b strings.Builder
		b.WriteString(reqLine)
		b.WriteString("Host: " + u.Host + "\r\n")

		for k, v := range final {
			if strings.EqualFold(k, "Host") {
				continue
			}
			if method == "POST" && strings.EqualFold(k, "Content-Type") {
				continue
			}
			b.WriteString(k + ": " + v + "\r\n")
		}

		if method == "POST" && body != "" {
			if _, hasCT := final["Content-Type"]; !hasCT {
				b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			}
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}

		b.WriteString("\r\n")
		if method == "POST" && body != "" {
			b.WriteString(body)
		}

		c.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := c.Write([]byte(b.String())); err != nil {
			return "", err
		}

		rd := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return "", err
			}
			head.WriteString(line)
			if strings.HasSuffix(head.String(), "\r\n\r\n") {
				break
			}
			if head.Len() > 64*1024 {
				break
			}
		}
		return strings.TrimSuffix(head.String(), "\r\n\r\n"), nil
	}

	if proxyURL == "" {
		conn, err = net.DialTimeout("tcp", host, dialTimeout)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		needTLS := (u.Scheme == "https")
		return readHead(conn, "", needTLS)
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	if pURL.Scheme != "http" {
		return "", fmt.Errorf("proxy scheme not supported for raw read: %s", pURL.Scheme)
	}
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":80"
	}
	conn, err = net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if u.Scheme == "http" {
		return readHead(conn, u.String(), false)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		respHead.WriteString(line)
		if strings.HasSuffix(respHead.String(), "\r\n\r\n") {
			break
		}
		if respHead.Len() > 32*1024 {
			break
		}
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") {
		return "", fmt.Errorf("proxy CONNECT failed")
	}

	return readHead(conn, "", true)
}

// -------------------- Auxiliares --------------------

func isHTML(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func readBodyDecodedLimit(resp *http.Response, max int64) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	var r io.Reader = io.LimitReader(resp.Body, max)

	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(io.LimitReader(resp.Body, max))
		if err != nil {
			return io.ReadAll(r)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "deflate":
		fr := flate.NewReader(io.LimitReader(resp.Body, max))
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return io.ReadAll(r)
	}
}

func formatVuln(kind, method, urlStr, detail string) string {
	if onlyPOC {
		return fmt.Sprintf("%s%s | %s%s", colorRed, urlStr, kind, colorReset)
	}
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
	return colorRed + msg + colorReset
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func parseScanOptions(opt string) map[int]bool {
	opt = strings.TrimSpace(opt)
	if opt == "" {
		return nil
	}
	m := make(map[int]bool)
	for _, p := range strings.Split(opt, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			m[n] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// -------------------- Link Manipulation (básico) --------------------

func linkManipulationMatch(body []byte, domain string) (bool, string) {
	low := strings.ToLower(string(body))
	dom := regexp.QuoteMeta(strings.ToLower(domain))

	patterns := []string{
		`src=["']https://` + dom,
		`href=["']https://` + dom,
		`action=["']https://` + dom,
		`\.href\s*=\s*["']https://` + dom,
		`html\s*=\s*["']https://` + dom,
		`eval\s*\(\s*['"]https://` + dom,
		`location\s*=\s*["']https://` + dom,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if loc := re.FindStringIndex(low); loc != nil {
			start := loc[0]
			end := loc[1]
			ctxStart := start - 40
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 40
			if ctxEnd > len(low) {
				ctxEnd = len(low)
			}
			return true, "match: " + strings.TrimSpace(low[ctxStart:ctxEnd])
		}
	}
	return false, ""
}
