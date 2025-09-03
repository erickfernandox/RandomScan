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
	flag.Usage = usage
}

func usage() {
	fmt.Println(`
Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject (random sample)
  -proxy    Proxy address (HTTP proxy supported in raw CRLF check)
  -H        Headers (repeatable)
  -s        Show only PoC (hide "Not Vulnerable")
  -html     Only print XSS/Link results if Content-Type is text/html
  -t        Number of threads (default 50, minimum 15)
`)
}

// -------------------- Main --------------------

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

// -------------------- Util de arquivo/params --------------------

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

// -------------------- Headers padrão --------------------

func defaultHeaderMap() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding": "gzip, deflate, br", // ATENÇÃO: stdlib não decodifica br
		"Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7,ar;q=0.6",
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

func mergeHeaders(base map[string]string, override map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

// -------------------- HTTP client e headers --------------------

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DialContext:        (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		DisableCompression: true, // vamos decodificar manualmente (gzip/deflate)
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
	final := mergeHeaders(base, user) // -H sobrescreve padrão
	for k, v := range final {
		req.Header.Set(k, v)
	}
}

// -------------------- Montagem de query/body "raw" --------------------

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

// -------------------- Test cases --------------------

type TestCase struct {
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
			Name:     "XSS",
			Payloads: []string{`%27%22teste`},
			NeedHTML: true,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
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
			Name:     "Redirect/SSRF",
			Payloads: []string{`https://example.com`},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
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
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
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
		{
			Name: "SSTI",
			Payloads: []string{
				`{{7*7}}efxtech`,
				`${{7*7}}efxtech`,
				`*{7*7}efxtech`,
			},
			NeedHTML: false,
			Detector: func(method, urlStr string, resp *http.Response, body []byte, sentBody string) (bool, string) {
				if contains(body, "49efxtech") {
					return true, "match: 49efxtech"
				}
				return false, ""
			},
		},
	}

	var results []string

	for _, tc := range tests {
		for _, payload := range tc.Payloads {
			// -------- GET --------
			getURL, ok := addParamsRaw(base, selectedParams, payload)
			if ok {
				req, err := http.NewRequest("GET", getURL, nil)
				if err == nil {
					applyHeaders(req)
					if resp, err := client.Do(req); err == nil {
						body, _ := readBodyDecodedLimit(resp, 2<<20) // 2MB
						resp.Body.Close()
						if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
							if vul, detail := tc.Detector("GET", getURL, resp, body, ""); vul {
								results = append(results, formatVuln(tc.Name, "GET", getURL, detail))
							} else if !onlyPOC {
								results = append(results, formatNotVuln(tc.Name, "GET", getURL))
							}
						}
					}
				}
			}

			// -------- POST (application/x-www-form-urlencoded) --------
			postURL := base
			bodyStr := buildFormBodyRaw(selectedParams, payload)
			req, err := http.NewRequest("POST", postURL, strings.NewReader(bodyStr))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				applyHeaders(req)
				if resp, err := client.Do(req); err == nil {
					body, _ := readBodyDecodedLimit(resp, 2<<20)
					resp.Body.Close()
					if (!tc.NeedHTML || isHTML(resp)) && (!htmlOnly || !tc.NeedHTML || isHTML(resp)) {
						if vul, detail := tc.Detector("POST", postURL, resp, body, bodyStr); vul {
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

// -------------------- Leitura bruta dos headers (CRLF) --------------------

// fetchRawResponseHead abre conexão (HTTP/HTTPS, com/sem proxy HTTP),
// envia o request "na unha" e retorna apenas o bloco de headers (até \r\n\r\n).
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

	// headers padrão + sobrescrita do usuário
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

	// Via HTTP proxy
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

	// HTTPS via CONNECT
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

// -------------------- Helpers --------------------

func isHTML(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func contains(body []byte, s string) bool { return strings.Contains(string(body), s) }

// decodifica gzip/deflate quando necessário (brotli não suportado na stdlib)
func readBodyDecodedLimit(resp *http.Response, max int64) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	var r io.Reader = io.LimitReader(resp.Body, max)

	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(io.LimitReader(resp.Body, max))
		if err != nil {
			return io.ReadAll(r) // fallback cru
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

func readAllLimit(r io.ReadCloser, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

var stripANSIRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
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
