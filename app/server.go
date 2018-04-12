// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	l4g "github.com/alecthomas/log4go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/store"
	"github.com/WTHealth/server/utils"
)

type Server struct {
	Store           store.Store
	Router          *mux.Router
	Server          *http.Server
	ListenAddr      *net.TCPAddr

	didFinishListen chan struct{}
}

var allowedMethods []string = []string{
	"POST",
	"GET",
	"OPTIONS",
	"PUT",
	"PATCH",
	"DELETE",
}

type RecoveryLogger struct {
}

func (rl *RecoveryLogger) Println(i ...interface{}) {
	l4g.Error("Please check the std error output for the stack trace")
	l4g.Error(i)
}

type CorsWrapper struct {
	config model.ConfigFunc
	router *mux.Router
}

func (cw *CorsWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if allowed := *cw.config().ServiceSettings.AllowCorsFrom; allowed != "" {
		if utils.CheckOrigin(r, allowed) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))

			if r.Method == "OPTIONS" {
				w.Header().Set(
					"Access-Control-Allow-Methods",
					strings.Join(allowedMethods, ", "))

				w.Header().Set(
					"Access-Control-Allow-Headers",
					r.Header.Get("Access-Control-Request-Headers"))
			}
		}
	}

	if r.Method == "OPTIONS" {
		return
	}

	cw.router.ServeHTTP(w, r)
}

const TIME_TO_WAIT_FOR_CONNECTIONS_TO_CLOSE_ON_SERVER_SHUTDOWN = time.Second

func redirectHTTPToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
	}

	url := r.URL
	url.Host = r.Host
	url.Scheme = "https"
	http.Redirect(w, r, url.String(), http.StatusFound)
}

func (a *App) StartServer() error {
	l4g.Info("api.server.start_server.starting.info")

	var handler http.Handler = &CorsWrapper{a.Config, a.Srv.Router}

	a.Srv.Server = &http.Server{
		Handler:      handlers.RecoveryHandler(handlers.RecoveryLogger(&RecoveryLogger{}), handlers.PrintRecoveryStack(true))(handler),
		ReadTimeout:  time.Duration(*a.Config().ServiceSettings.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(*a.Config().ServiceSettings.WriteTimeout) * time.Second,
	}

	addr := *a.Config().ServiceSettings.ListenAddress
	if addr == "" {
		if *a.Config().ServiceSettings.ConnectionSecurity == model.CONN_SECURITY_TLS {
			addr = ":https"
		} else {
			addr = ":http"
		}
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		errors.Wrapf(err, "api.server.start_server.starting.critical", err)
		return err
	}
	a.Srv.ListenAddr = listener.Addr().(*net.TCPAddr)

	l4g.Info("api.server.start_server.listening.info", listener.Addr().String())

	// Migration from old let's encrypt library
	if *a.Config().ServiceSettings.UseLetsEncrypt {
		if stat, err := os.Stat(*a.Config().ServiceSettings.LetsEncryptCertificateCacheFile); err == nil && !stat.IsDir() {
			os.Remove(*a.Config().ServiceSettings.LetsEncryptCertificateCacheFile)
		}
	}

	m := &autocert.Manager{
		Cache:  autocert.DirCache(*a.Config().ServiceSettings.LetsEncryptCertificateCacheFile),
		Prompt: autocert.AcceptTOS,
	}

	if *a.Config().ServiceSettings.Forward80To443 {
		if host, port, err := net.SplitHostPort(addr); err != nil {
			l4g.Error("Unable to setup forwarding: " + err.Error())
		} else if port != "443" {
			return fmt.Errorf("api.server.start_server.forward80to443.enabled_but_listening_on_wrong_port", port)
		} else {
			httpListenAddress := net.JoinHostPort(host, "http")

			if *a.Config().ServiceSettings.UseLetsEncrypt {
				go http.ListenAndServe(httpListenAddress, m.HTTPHandler(nil))
			} else {
				go func() {
					redirectListener, err := net.Listen("tcp", httpListenAddress)
					if err != nil {
						l4g.Error("Unable to setup forwarding: " + err.Error())
						return
					}
					defer redirectListener.Close()

					http.Serve(redirectListener, http.HandlerFunc(redirectHTTPToHTTPS))
				}()
			}
		}
	} else if *a.Config().ServiceSettings.UseLetsEncrypt {
		return errors.New("api.server.start_server.forward80to443.disabled_while_using_lets_encrypt")
	}

	a.Srv.didFinishListen = make(chan struct{})
	go func() {
		var err error
		if *a.Config().ServiceSettings.ConnectionSecurity == model.CONN_SECURITY_TLS {
			if *a.Config().ServiceSettings.UseLetsEncrypt {

				tlsConfig := &tls.Config{
					GetCertificate: m.GetCertificate,
				}

				tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")

				a.Srv.Server.TLSConfig = tlsConfig
				err = a.Srv.Server.ServeTLS(listener, "", "")
			} else {
				err = a.Srv.Server.ServeTLS(listener, *a.Config().ServiceSettings.TLSCertFile, *a.Config().ServiceSettings.TLSKeyFile)
			}
		} else {
			err = a.Srv.Server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			l4g.Critical("api.server.start_server.starting.critical", err)
			time.Sleep(time.Second)
		}
		close(a.Srv.didFinishListen)
	}()

	return nil
}

func (a *App) StopServer() {
	if a.Srv.Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), TIME_TO_WAIT_FOR_CONNECTIONS_TO_CLOSE_ON_SERVER_SHUTDOWN)
		defer cancel()
		didShutdown := false
		for a.Srv.didFinishListen != nil && !didShutdown {
			if err := a.Srv.Server.Shutdown(ctx); err != nil {
				l4g.Warn(err.Error())
			}
			timer := time.NewTimer(time.Millisecond * 50)
			select {
			case <-a.Srv.didFinishListen:
				didShutdown = true
			case <-timer.C:
			}
			timer.Stop()
		}
		a.Srv.Server.Close()
		a.Srv.Server = nil
	}
}