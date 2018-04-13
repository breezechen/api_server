// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/http"
	"sync/atomic"

	l4g "github.com/alecthomas/log4go"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/store"
	"github.com/WTHealth/server/store/sqlstore"
	"github.com/WTHealth/server/utils"
)

type App struct {
	goroutineCount      int32
	goroutineExitSignal chan struct{}

	Srv *Server

	config     atomic.Value
	configFile string

	siteURL string

	newStore func() store.Store
}

var appCount = 0

// New creates a new App. You must call Shutdown when you're done with it.
// XXX: For now, only one at a time is allowed as some resources are still shared.
func New(options ...Option) (outApp *App, outErr error) {
	appCount++
	if appCount > 1 {
		panic("Only one App should exist at a time. Did you forget to call Shutdown()?")
	}

	app := &App{
		goroutineExitSignal: make(chan struct{}, 1),
		Srv: &Server{
			Router: mux.NewRouter(),
		},
		configFile: "config.json",
	}
	defer func() {
		if outErr != nil {
			app.Shutdown()
		}
	}()

	if utils.T == nil {
		if err := utils.TranslationsPreInit(); err != nil {
			return nil, errors.Wrapf(err, "unable to load Mattermost translation files")
		}
	}
	model.AppErrorInit(utils.T)

	for _, option := range options {
		option(app)
	}

	if err := app.LoadConfig(app.configFile); err != nil {
		return nil, err
	}

	l4g.Info("api.server.new_server.init.info")

	if app.newStore == nil {
		app.newStore = func() store.Store {
			return store.NewLayeredStore(sqlstore.NewSqlSupplier(app.Config().SqlSettings))
		}
	}

	app.Srv.Store = app.newStore()

	app.Srv.Router.NotFoundHandler = http.HandlerFunc(app.Handle404)

	return app, nil
}

func (a *App) Shutdown() {
	appCount--

	l4g.Info("api.server.stop_server.stopping.info")

	a.StopServer()

	a.WaitForGoroutines()

	if a.Srv.Store != nil {
		a.Srv.Store.Close()
	}
	a.Srv = nil

	l4g.Info("api.server.stop_server.stopped.info")
}

// Go creates a goroutine, but maintains a record of it to ensure that execution completes before
// the app is destroyed.
func (a *App) Go(f func()) {
	atomic.AddInt32(&a.goroutineCount, 1)

	go func() {
		f()

		atomic.AddInt32(&a.goroutineCount, -1)
		select {
		case a.goroutineExitSignal <- struct{}{}:
		default:
		}
	}()
}

// WaitForGoroutines blocks until all goroutines created by App.Go exit.
func (a *App) WaitForGoroutines() {
	for atomic.LoadInt32(&a.goroutineCount) != 0 {
		<-a.goroutineExitSignal
	}
}

func (a *App) Handle404(w http.ResponseWriter, r *http.Request) {
	err := model.NewAppError("Handle404", "api.context.404.app_error", nil, "", http.StatusNotFound)

	l4g.Debug("%v: code=404 ip=%v", r.URL.Path, utils.GetIpAddress(r))

	utils.RenderWebAppError(w, r, err)
}
