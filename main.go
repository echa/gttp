package main

import (
	"bytes"
	_ "crypto/md5"    // make MD5 hash available for signature check
	_ "crypto/sha256" // make SHA224/256 hashes available for signature check
	_ "crypto/sha512" // make SHA384/512 hashes available for signature check
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/daviddengcn/go-colortext"
)

/*
TODO:
    allow setting content-type for uploaded files
    disable json formatting if output is not terminal (isatty)
    read password from terminal if no password given ( https://github.com/howeyc/gopass )
*/

type kvtype int

const (
	kvpUnknown kvtype = iota
	kvpHeader
	kvpQuery
	kvpBody
	kvpJSON
	kvpFile
)

type kvpairs struct {
	headers map[string]string
	query   map[string][]string
	body    map[string][]string
	js      map[string]string
	file    map[string]string // filename, not content
}

func unescape(s string) string {
	u := make([]rune, 0, len(s))
	var escape bool
	for _, c := range s {
		if escape {
			u = append(u, c)
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			continue
		}
		u = append(u, c)
	}

	return string(u)
}

func parseKeyValue(keyvalue string) (kvtype, string, string) {

	k := make([]rune, 0, len(keyvalue))
	var escape bool
	for i, c := range keyvalue {
		if escape {
			k = append(k, c)
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			continue
		}
		// TODO(dgryski): make sure we don't overstep the array
		if c == ':' {
			if i+1 < len(keyvalue) && keyvalue[i+1] == '=' {
				// found ':=', a raw json param
				return kvpJSON, string(k), unescape(keyvalue[i+2:])
			}
			// found ':' , a header
			return kvpHeader, string(k), unescape(keyvalue[i+1:])
		} else if c == '=' {
			if i+1 < len(keyvalue) && keyvalue[i+1] == '=' {
				// found '==', a query param
				return kvpQuery, string(k), unescape(keyvalue[i+2:])
			}
			// found '=' , a form value
			return kvpBody, string(k), unescape(keyvalue[i+1:])
		} else if c == '@' {
			return kvpFile, string(k), unescape(keyvalue[i+1:])
		}
		k = append(k, c)
	}

	return kvpUnknown, "", ""
}

func parseArgs(args []string) (*kvpairs, error) {
	kvp := kvpairs{
		headers: make(map[string]string),
		query:   make(map[string][]string),
		js:      make(map[string]string),
		body:    make(map[string][]string),
		file:    make(map[string]string),
	}

	for _, arg := range args {

		t, k, v := parseKeyValue(arg)

		switch t {

		case kvpUnknown:
			return nil, errors.New("bad key/value: " + arg)

		case kvpHeader:
			kvp.headers[k] = v

		case kvpQuery:
			vs := kvp.query[k]
			kvp.query[k] = append(vs, v)

		case kvpBody:
			vs := kvp.query[k]
			kvp.body[k] = append(vs, v)

		case kvpJSON:
			kvp.js[k] = v

		case kvpFile:
			kvp.file[k] = v
		}
	}

	return &kvp, nil
}

func addValues(values url.Values, key string, vals interface{}) {

	switch val := vals.(type) {
	case bool:
		if val {
			values.Add(key, "true")
		} else {
			values.Add(key, "false")
		}
	case string:
		values.Add(key, val)
	case float64:
		values.Add(key, fmt.Sprintf("%g", val))
	case map[string]interface{}:
		for k := range val {
			addValues(values, key, k)
		}
	case []interface{}:
		for _, v := range val {
			addValues(values, key, v)
		}
	default:
		log.Println("unknown type: ", reflect.TypeOf(val))
	}
}

var (
	h2c            bool
	host           string
	postform       bool
	showHeaders    bool
	verbose        bool
	auth           string
	nocolor        bool
	noFormatting   bool
	rawOutput      bool
	useMultipart   bool
	timeout        time.Duration
	insecure       bool
	useEnv         bool
	method         string
	clientCertFile string
	clientKeyFile  string
)

func init() {
	flag.BoolVar(&h2c, "h2c", false, "enable h2c (HTTP/2 without TLS)")
	flag.StringVar(&host, "host", "", "overwrite http host header (may use with proxy)")
	flag.BoolVar(&postform, "f", false, "post form")
	flag.BoolVar(&showHeaders, "headers", false, "show headers")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.StringVar(&auth, "auth", "", "username:password")
	flag.BoolVar(&nocolor, "nocolor", false, "disable color output")
	flag.BoolVar(&noFormatting, "n", false, "no formatting/color")
	flag.BoolVar(&rawOutput, "raw", false, "raw output (no headers/formatting/color)")
	flag.BoolVar(&useMultipart, "m", true, "use multipart if uploading files")
	flag.DurationVar(&timeout, "t", 0, "timeout (default none)")
	flag.BoolVar(&insecure, "k", false, "allow insecure TLS")
	flag.BoolVar(&useEnv, "e", true, "use proxies from environment")
	flag.StringVar(&method, "X", http.MethodGet, "HTTP method")
	flag.StringVar(&clientCertFile, "cert", "", "TLS client certificate")
	flag.StringVar(&clientKeyFile, "key", "", "TLS client key")
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	if noFormatting {
		nocolor = true
	}

	if rawOutput {
		showHeaders = false
		nocolor = true
		noFormatting = true
	}

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	args := flag.Args()

	methodProvided := false
	if postform {
		methodProvided = true
		if method == http.MethodGet {
			method = http.MethodPost
		}
	}

	switch args[0] {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "PURGE", "TRACE", "OPTIONS", "CONNECT", "PATCH":
		methodProvided = true
		method = args[0]
		args = args[1:]
	}

	// add http:// if we need it
	if !strings.HasPrefix(args[0], "http://") && !strings.HasPrefix(args[0], "https://") {
		args[0] = "http://" + args[0]
	}
	u := args[0]
	args = args[1:]

	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		log.Fatal("error creating request object: ", err)
	}

	if host != "" {
		req.Host = host
	}

	if auth != "" {
		s := strings.SplitN(auth, ":", 2)
		req.SetBasicAuth(s[0], s[1])
	}

	kvp, err := parseArgs(args)
	if err != nil {
		log.Fatal(err)
	}

	var postFiles bool
	rawBodyFilename := "" // name of file for raw body
	bodyparams := make(map[string]interface{})

	// update the raw query if we have any new parameters
	if len(kvp.query) > 0 {
		queryparams := req.URL.Query()
		for k, vs := range kvp.query {
			for _, v := range vs {
				queryparams.Add(k, v)
			}
		}
		req.URL.RawQuery = queryparams.Encode()
	}

	for k, v := range kvp.body {
		if len(v) == 1 {
			bodyparams[k] = v[0]
		} else {
			bodyparams[k] = v
		}
	}

	for k, v := range kvp.js {
		var vint interface{}
		if err = json.Unmarshal([]byte(v), &vint); err != nil {
			log.Fatal("invalid json: key", k, "value", v)
		}
		bodyparams[k] = vint
	}

	// if we have at least one file, maybe upload with multipart
	postFiles = len(kvp.file) > 0

	for k, v := range kvp.file {
		if k == "-" {
			rawBodyFilename = v
			// but we're no longer posting files
			postFiles = false
		}
	}

	// assemble the body

	var body []byte

	if rawBodyFilename != "" {
		if len(kvp.file) > 1 {
			log.Fatal("only one input file allowed when setting raw body")
		}

		if len(bodyparams) > 0 {
			log.Println("extra body parameters ignored when setting raw body")
		}

		var file *os.File
		if file, err = os.Open(rawBodyFilename); err != nil {
			log.Fatal("unable to open file for body: ", err)
		}
		defer file.Close()

		body, err = ioutil.ReadAll(file)
		if err != nil {
			log.Fatal("error reading body contents: ", err)
		}

		req.Header.Add("Content-Type", "application/octet-stream")

	} else if postFiles && useMultipart {

		// we have at least one file name
		buf := &bytes.Buffer{}

		// write the files
		writer := multipart.NewWriter(buf)
		for k, v := range kvp.file {
			var part io.Writer
			if part, err = writer.CreateFormFile(k, filepath.Base(v)); err != nil {
				log.Fatal("unable to create form file: ", err)
			}
			var file *os.File
			if file, err = os.Open(v); err != nil {
				log.Fatal("unable to open file: ", err)
			}
			defer file.Close()
			if _, err = io.Copy(part, file); err != nil {
				log.Fatal("unable to write file: ", err)
			}
		}

		// construct the extra body parameters
		values := url.Values{}
		for k, v := range bodyparams {
			addValues(values, k, v)
		}

		// and write them into the body
		for k, v := range values {
			for _, vv := range v {
				writer.WriteField(k, vv)
			}
		}

		writer.Close()

		body = buf.Bytes()
		req.Header.Add("Content-Type", writer.FormDataContentType())

	} else if len(bodyparams) > 0 || len(kvp.file) > 0 {

		// add our files as body values
		for k, v := range kvp.file {
			var file *os.File
			if file, err = os.Open(v); err != nil {
				log.Fatal("unable to open file for body: ", err)
			}
			defer file.Close()

			var val []byte
			if val, err = ioutil.ReadAll(file); err != nil {
				log.Fatal("error reading body contents: ", err)
			}
			// string so that we get file contents and not base64 encoded contents
			bodyparams[k] = string(val)
		}

		if postform {
			values := url.Values{}
			for k, v := range bodyparams {
				addValues(values, k, v)
			}
			body = []byte(values.Encode())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			body, _ = json.Marshal(bodyparams)
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if !methodProvided {
			req.Method = "POST"
		}
	}

	defaultHeaders := map[string]string{
		"User-Agent": "gttp - http for gophers",
		"Accept":     "*/*",
		"Host":       req.URL.Host,
	}

	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	for k, v := range kvp.headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	if verbose {
		printRequestHeaders(nocolor, req)
		os.Stdout.Write(body)
		os.Stdout.Write([]byte{'\n', '\n'})
	}

	client := http.DefaultClient

	if h2c {
		client.Transport = &http2.Transport{
			DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
			AllowHTTP: true,
		}
		tlsc := &tls.Config{
			InsecureSkipVerify: insecure,
		}
		if clientCertFile != "" && clientKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				log.Fatalf("Could not load TLS client cert or key [%s]: %v", clientCertFile, err)
			}
			tlsc.Certificates = []tls.Certificate{cert}
			tlsc.BuildNameToCertificate()
		}
		client.Transport.(*http2.Transport).TLSClientConfig = tlsc
	} else {
		client.Transport = http.DefaultTransport
		if req.URL.Scheme == "https" {
			tlsc := &tls.Config{
				InsecureSkipVerify: insecure,
			}
			if clientCertFile != "" && clientKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
				if err != nil {
					log.Fatalf("Could not load TLS client cert or key [%s]: %v", clientCertFile, err)
				}
				tlsc.Certificates = []tls.Certificate{cert}
				tlsc.BuildNameToCertificate()
			}
			client.Transport.(*http.Transport).TLSClientConfig = tlsc
		}
	}

	if timeout != 0 {
		client.Timeout = timeout
	}

	if !useEnv {
		client.Transport.(*http.Transport).Proxy = nil
	}

	response, err := client.Do(req)

	if err != nil {
		log.Fatal("error during fetch:", err)
	}

	if showHeaders || verbose {
		printResponseHeaders(nocolor, response)
	}

	body, _ = ioutil.ReadAll(response.Body)
	response.Body.Close()

	if response.StatusCode >= 400 {
		log.Printf("%d %s\n", response.StatusCode, http.StatusText(response.StatusCode))
	}

	if rawOutput {
		os.Stdout.Write(body)
	} else if noFormatting {
		if bytes.IndexByte(body, 0) != -1 {
			os.Stdout.Write([]byte(msgNoBinaryToTerminal))
		} else {
			os.Stdout.Write(body)
		}
	} else {
		// maybe do some formatting
		switch {
		case strings.HasPrefix(response.Header.Get("Content-type"), "application/json"):
			var j interface{}
			d := json.NewDecoder(bytes.NewReader(body))
			d.UseNumber()
			d.Decode(&j)
			if nocolor {
				body, _ = json.MarshalIndent(j, "", "    ")
				os.Stdout.Write(body)
			} else {
				printJSON(1, j, false)
			}

		case strings.HasPrefix(response.Header.Get("Content-type"), "text/"):
			os.Stdout.Write(body)

		case bytes.IndexByte(body, 0) != -1:
			// at least one 0 byte, assume it's binary data :/
			// silly, but it's the same heuristic as httpie
			os.Stdout.Write([]byte(msgNoBinaryToTerminal))

		default:
			os.Stdout.Write(body)
		}
	}

	if showHeaders {
		// formatted output ends with two newlines
		os.Stdout.Write([]byte{'\n', '\n'})
		printResponseTrailers(nocolor, response)
	}
}

func printJSON(depth int, val interface{}, isKey bool) {
	switch v := val.(type) {
	case nil:
		ct.ChangeColor(ct.Blue, false, ct.None, false)
		fmt.Print("null")
		ct.ResetColor()
	case bool:
		ct.ChangeColor(ct.Blue, false, ct.None, false)
		if v {
			fmt.Print("true")
		} else {
			fmt.Print("false")
		}
		ct.ResetColor()
	case string:
		if isKey {
			ct.ChangeColor(ct.Blue, true, ct.None, false)
		} else {
			ct.ChangeColor(ct.Yellow, false, ct.None, false)
		}
		fmt.Print(strconv.Quote(v))
		ct.ResetColor()
	case json.Number:
		ct.ChangeColor(ct.Blue, false, ct.None, false)
		fmt.Print(v)
		ct.ResetColor()
	case map[string]interface{}:

		if len(v) == 0 {
			fmt.Print("{}")
			break
		}

		var keys []string

		for h := range v {
			keys = append(keys, h)
		}

		sort.Strings(keys)

		fmt.Println("{")
		needNL := false
		for _, key := range keys {
			if needNL {
				fmt.Print(",\n")
			}
			needNL = true
			for i := 0; i < depth; i++ {
				fmt.Print("    ")
			}

			printJSON(depth+1, key, true)
			fmt.Print(": ")
			printJSON(depth+1, v[key], false)
		}
		fmt.Println("")

		for i := 0; i < depth-1; i++ {
			fmt.Print("    ")
		}
		fmt.Print("}")

	case []interface{}:

		if len(v) == 0 {
			fmt.Print("[]")
			break
		}

		fmt.Println("[")
		needNL := false
		for _, e := range v {
			if needNL {
				fmt.Print(",\n")
			}
			needNL = true
			for i := 0; i < depth; i++ {
				fmt.Print("    ")
			}

			printJSON(depth+1, e, false)
		}
		fmt.Println("")

		for i := 0; i < depth-1; i++ {
			fmt.Print("    ")
		}
		fmt.Print("]")
	default:
		fmt.Println("unknown type:", reflect.TypeOf(v))
	}
}

func printRequestHeaders(noColor bool, request *http.Request) {

	u := request.URL.Path
	if u == "" {
		u = "/"
	}

	if request.URL.RawQuery != "" {
		u += "?" + request.URL.RawQuery
	}

	if noColor {
		fmt.Printf("%s %s %s", request.Method, u, request.Proto)
	} else {
		ct.ChangeColor(ct.Green, false, ct.None, false)
		fmt.Printf("%s", request.Method)
		ct.ChangeColor(ct.Cyan, false, ct.None, false)
		fmt.Printf(" %s", u)
		ct.ChangeColor(ct.Blue, false, ct.None, false)
		fmt.Printf(" %s", request.Proto)
	}

	fmt.Println()
	printHeaders(noColor, request.Header)
	fmt.Println()
}

func printResponseHeaders(noColor bool, response *http.Response) {
	if noColor {
		fmt.Printf("%s %s", response.Proto, response.Status)
	} else {
		ct.ChangeColor(ct.Blue, false, ct.None, false)
		fmt.Printf("%s %s", response.Proto, response.Status[:3])
		ct.ChangeColor(ct.Cyan, false, ct.None, false)
		fmt.Printf("%s", response.Status[3:])
	}

	fmt.Println()
	printHeaders(noColor, response.Header)
	fmt.Println()
}

func printResponseTrailers(noColor bool, response *http.Response) {
	printHeaders(noColor, response.Trailer)
	fmt.Println()
}

func printHeaders(noColor bool, headers http.Header) {

	var keys []string

	for h := range headers {
		keys = append(keys, h)
	}

	sort.Strings(keys)

	if noColor {
		for _, k := range keys {
			if len(headers[k]) > 0 {
				fmt.Printf("%s: %s\n", k, headers[k][0])
			}
		}
	} else {
		for _, k := range keys {
			ct.ChangeColor(ct.Cyan, false, ct.None, false)
			fmt.Printf("%s", k)
			ct.ChangeColor(ct.Black, false, ct.None, false)
			ct.ResetColor()
			fmt.Printf(": ")
			ct.ChangeColor(ct.Yellow, false, ct.None, false)
			if len(headers[k]) > 0 {
				fmt.Printf("%s", headers[k][0])
			}
			ct.ResetColor()
			fmt.Println()
		}
	}
}

const msgNoBinaryToTerminal = "\n\n" +
	"+-----------------------------------------+\n" +
	"| NOTE: binary data not shown in terminal |\n" +
	"+-----------------------------------------+"
