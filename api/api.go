// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/WTHealth/server/app"
	"github.com/WTHealth/server/model"

	_ "github.com/nicksnyder/go-i18n/i18n"
)

type Routes struct {
	Root    *mux.Router // ''
	ApiRoot *mux.Router // 'api/v1'

	Users    *mux.Router // 'api/v1/users'
}

type API struct {
	App        *app.App
	BaseRoutes *Routes
}

func Init(a *app.App, root *mux.Router) *API {
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
	}
	api.BaseRoutes.Root = root
	api.BaseRoutes.ApiRoot = root.PathPrefix(model.API_URL_SUFFIX_V1).Subrouter()
	api.BaseRoutes.Users = api.BaseRoutes.ApiRoot.PathPrefix("/users").Subrouter()

	api.InitUser()

	// 404 on any api route before web.go has a chance to serve it
	root.Handle("/api/{anything:.*}", http.HandlerFunc(api.Handle404))

	return api
}

func (api *API) Handle404(w http.ResponseWriter, r *http.Request) {
	Handle404(api.App, w, r)
}
