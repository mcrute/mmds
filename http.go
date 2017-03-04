package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	jww "github.com/spf13/jwalterweatherman"
)

const (
	APP_CTX_KEY = "app"
)

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// Do the same thing ListenAndServe does but allow passing in the listener
// instead of the address so that we can bind privileged ports before dropping
// permissions to start the server itself.
func ListenAndServeRaw(ln net.Listener, handler http.Handler) error {
	server := &http.Server{Addr: ln.Addr().String(), Handler: handler}
	return server.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}

// Handler that pushes the application context onto the request context stack
// so that it's available to all other handlers in the stack.
type ContextAwareHandler struct {
	ctx     *appContext
	handler http.HandlerFunc
}

func (h ContextAwareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defaultHeaders(w)
	h.handler(w, r.WithContext(context.WithValue(r.Context(), APP_CTX_KEY, h.ctx)))
}

// Handler that is able to inspect the application context and print out the
// value of specific fields.
type ContextPrintingHandler struct {
	ctx   *appContext
	field string
}

func (h ContextPrintingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defaultHeaders(w)

	c := reflect.ValueOf(h.ctx)
	f := reflect.Indirect(c).FieldByName(h.field)

	switch i := f.Interface().(type) {
	case fmt.Stringer:
		fmt.Fprintln(w, i.String())
	case *string:
		if i == nil {
			fmt.Fprintln(w, "")
		} else {
			fmt.Fprintln(w, *i)
		}
	default:
		fmt.Fprintln(w, i)
	}
}

// Print default headers for JSON data
func defaultHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Server", "EC2ws")
	w.Header().Set("Connection", "close")
}

// Write out JSON data in formatted form or an error
func writeHTTPJson(w http.ResponseWriter, data interface{}, name string) {
	jd, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		jww.ERROR.Printf("Error marshaling json in %s: %s", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	fmt.Fprintf(w, string(jd))
}

// Get the application context from the request context
func getAppCtx(r *http.Request) *appContext {
	return r.Context().Value(APP_CTX_KEY).(*appContext)
}

// Handler that will reject non-local requests in case the daemon gets bound
// incorrectly to a public interface
type SecurityHandler struct {
	handler http.Handler
}

func (h SecurityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// String is ip:port formatted
	ip := strings.Split(r.RemoteAddr, ":")[0]

	if ip != "169.254.169.254" && ip != "127.0.0.1" {
		jww.ERROR.Printf("Non-local metadata request from %s!", ip)
		http.NotFound(w, r)
		return
	} else {
		h.handler.ServeHTTP(w, r)
	}
}
