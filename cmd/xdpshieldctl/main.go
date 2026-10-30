package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const usage = `usage: xdpshieldctl [-addr url] [-token t] <command>

  status                  vips and backends
  blocked                 current dynamic blocklist
  block <ip> [ttl]        block a source (needs token), ttl like 10m
  unblock <ip>            (needs token)
  reload                  re-read the config now (needs token), prints why if rejected
  events [n]              recent block events, newest first
  stats                   datapath counters from /metrics
  top [seconds]           live rates, refreshed until ctrl-c
`

type client struct {
	base  string
	token string
	http  *http.Client
}

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *client) do(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var e envelope
		if json.Unmarshal(raw, &e) == nil && e.Error != nil {
			return nil, fmt.Errorf("%s: %s", e.Error.Code, e.Error.Message)
		}
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return raw, nil
}

func (c *client) get(path string, into any) error {
	raw, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return err
	}
	return json.Unmarshal(e.Data, into)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("xdpshieldctl", flag.ContinueOnError)
	fs.SetOutput(errw)
	addr := fs.String("addr", "http://127.0.0.1:9100", "admin api address")
	token := fs.String("token", os.Getenv("XDPSHIELD_TOKEN"), "bearer token for block/unblock")
	fs.Usage = func() { fmt.Fprint(errw, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}

	c := &client{base: strings.TrimRight(*addr, "/"), token: *token, http: &http.Client{Timeout: 5 * time.Second}}
	rest := fs.Args()[1:]

	var err error
	switch fs.Arg(0) {
	case "status":
		err = c.status(out)
	case "blocked":
		err = c.blocked(out)
	case "block":
		if len(rest) < 1 || len(rest) > 2 {
			fmt.Fprint(errw, usage)
			return 2
		}
		ttl := ""
		if len(rest) == 2 {
			ttl = rest[1]
		}
		err = c.block(out, rest[0], ttl)
	case "unblock":
		if len(rest) != 1 {
			fmt.Fprint(errw, usage)
			return 2
		}
		_, err = c.do("DELETE", "/api/v1/blocklist/"+url.PathEscape(rest[0]), nil)
		if err == nil {
			fmt.Fprintln(out, "unblocked", rest[0])
		}
	case "reload":
		_, err = c.do("POST", "/api/v1/reload", nil)
		if err == nil {
			fmt.Fprintln(out, "config reloaded")
		}
	case "events":
		n := 20
		if len(rest) > 0 {
			if n, err = strconv.Atoi(rest[0]); err != nil || n <= 0 {
				fmt.Fprintln(errw, "events: n must be a positive number")
				return 2
			}
		}
		err = c.events(out, n)
	case "stats":
		err = c.stats(out)
	case "top":
		every := time.Second
		if len(rest) > 0 {
			n, convErr := strconv.Atoi(rest[0])
			if convErr != nil || n <= 0 {
				fmt.Fprintln(errw, "top: seconds must be a positive number")
				return 2
			}
			every = time.Duration(n) * time.Second
		}
		err = c.top(out, every)
	default:
		fmt.Fprint(errw, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}

func (c *client) status(out io.Writer) error {
	var st struct {
		VIPs []struct {
			Name string `json:"name"`
			ID   int    `json:"id"`
			Addr string `json:"address"`
			Port int    `json:"port"`
			UDP  bool   `json:"udp"`
		} `json:"vips"`
		Backends []struct {
			Name    string `json:"name"`
			ID      int    `json:"id"`
			Addr    string `json:"address"`
			Healthy bool   `json:"healthy"`
		} `json:"backends"`
	}
	if err := c.get("/api/v1/status", &st); err != nil {
		return err
	}

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VIP\tID\tADDRESS\tPROTO")
	for _, v := range st.VIPs {
		proto := "tcp"
		if v.UDP {
			proto = "udp"
		}
		host := v.Addr
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		fmt.Fprintf(w, "%s\t%d\t%s:%d\t%s\n", v.Name, v.ID, host, v.Port, proto)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "BACKEND\tID\tADDRESS\tHEALTH")
	for _, b := range st.Backends {
		h := "up"
		if !b.Healthy {
			h = "DOWN"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", b.Name, b.ID, b.Addr, h)
	}
	return w.Flush()
}

func (c *client) blocked(out io.Writer) error {
	var list []struct {
		Addr      string `json:"addr"`
		Reason    string `json:"reason"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := c.get("/api/v1/blocklist", &list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(out, "nothing blocked")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ADDRESS\tREASON\tEXPIRES IN")
	for _, e := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\n", e.Addr, e.Reason, e.ExpiresIn)
	}
	return w.Flush()
}

func (c *client) block(out io.Writer, ip, ttl string) error {
	body := map[string]string{"ip": ip}
	if ttl != "" {
		body["ttl"] = ttl
	}
	raw, _ := json.Marshal(body)
	if _, err := c.do("POST", "/api/v1/blocklist", strings.NewReader(string(raw))); err != nil {
		return err
	}
	fmt.Fprintln(out, "blocked", ip)
	return nil
}

func (c *client) events(out io.Writer, n int) error {
	var evs []struct {
		At     time.Time `json:"at"`
		Src    string    `json:"src"`
		Reason string    `json:"reason"`
		PPS    uint32    `json:"observed_pps"`
	}
	if err := c.get("/api/v1/events?limit="+strconv.Itoa(n), &evs); err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tSOURCE\tREASON\tPPS")
	for _, e := range evs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", e.At.Local().Format("15:04:05"), e.Src, e.Reason, e.PPS)
	}
	return w.Flush()
}

// plain text parse, no prometheus dependency needed for a handful of series
func (c *client) stats(out io.Writer) error {
	raw, err := c.do("GET", "/metrics", nil)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "xdpshield_") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		val, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\n", strings.TrimPrefix(line[:i], "xdpshield_"), human(val))
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return w.Flush()
}

func human(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.1fk", v/1e3)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
