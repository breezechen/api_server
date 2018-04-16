// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"net/http"
	"strings"

	l4g "github.com/alecthomas/log4go"
	goi18n "github.com/nicksnyder/go-i18n/i18n"

	"github.com/WTHealth/server/app"
	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
)

type Context struct {
	App           *app.App
	Session       model.Session
	Err           *model.AppError
	T             goi18n.TranslateFunc
	RequestId     string
	IpAddress     string
	Path          string
	siteURLHeader string
}

func (api *API) ApiHandler(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: false,
		trustRequester: false,
	}
}

func (api *API) ApiSessionRequired(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: true,
		trustRequester: false,
	}
}

func (api *API) ApiHandlerTrustRequester(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: false,
		trustRequester: true,
	}
}

func (api *API) ApiSessionRequiredTrustRequester(h func(*Context, http.ResponseWriter, *http.Request)) http.Handler {
	return &handler{
		app:            api.App,
		handleFunc:     h,
		requireSession: true,
		trustRequester: true,
	}
}

type handler struct {
	app            *app.App
	handleFunc     func(*Context, http.ResponseWriter, *http.Request)
	requireSession bool
	trustRequester bool
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l4g.Debug("%v", r.URL.Path)

	c := &Context{}
	c.App = h.app
	c.RequestId = model.NewId()
	c.IpAddress = utils.GetIpAddress(r)

	token, tokenLocation := app.ParseAuthTokenFromRequest(r)

	// CSRF Check
	if tokenLocation == app.TokenLocationCookie && h.requireSession && !h.trustRequester {
		if r.Header.Get(model.HEADER_REQUESTED_WITH) != model.HEADER_REQUESTED_WITH_XML {
			c.Err = model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token+" Appears to be a CSRF attempt", http.StatusUnauthorized)
			token = ""
		}
	}

	c.SetSiteURLHeader(app.GetProtocol(r) + "://" + r.Host)

	w.Header().Set(model.HEADER_REQUEST_ID, c.RequestId)

	w.Header().Set("Content-Type", "application/json")

	if len(token) != 0 {
		session, err := c.App.GetSession(token)

		if err != nil {
			l4g.Info(utils.T("api.context.invalid_session.error"), err.Error())
			if err.StatusCode == http.StatusInternalServerError {
				c.Err = err
			} else if h.requireSession {
				c.RemoveSessionCookie(w, r)
				c.Err = model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token, http.StatusUnauthorized)
			}
		} else if !session.IsOAuth && tokenLocation == app.TokenLocationQueryString {
			c.Err = model.NewAppError("ServeHTTP", "api.context.token_provided.app_error", nil, "token="+token, http.StatusUnauthorized)
		} else {
			c.Session = *session
		}
	}

	c.Path = r.URL.Path

	if c.Err == nil && h.requireSession {
		c.SessionRequired()
	}

	if c.Err == nil {
		h.handleFunc(c, w, r)
	}

	// Handle errors that have occoured
	if c.Err != nil {
		c.Err.Translate(c.T)
		c.Err.RequestId = c.RequestId

		if c.Err.Id == "api.context.session_expired.app_error" {
			c.LogInfo(c.Err)
		} else {
			c.LogError(c.Err)
		}

		c.Err.Where = r.URL.Path

		// Block out detailed error when not in developer mode
		if !*c.App.Config().ServiceSettings.EnableDeveloper {
			c.Err.DetailedError = ""
		}
		
		utils.ReplyApiError(w, r, c.Err)
	}
}

func (c *Context) LogError(err *model.AppError) {

	// filter out endless reconnects
	if c.Path == "/api/v1/users/websocket" && err.StatusCode == 401 || err.Id == "web.check_browser_compatibility.app_error" {
		c.LogDebug(err)
	} else if err.Id != "api.post.create_post.town_square_read_only" {
		l4g.Error("api.context.log.error", c.Path, err.Where, err.StatusCode,
			c.RequestId, c.Session.UserId, c.IpAddress, err.SystemMessage(utils.TDefault), err.DetailedError)
	}
}

func (c *Context) LogInfo(err *model.AppError) {
	l4g.Info(utils.TDefault("api.context.log.error"), c.Path, err.Where, err.StatusCode,
		c.RequestId, c.Session.UserId, c.IpAddress, err.SystemMessage(utils.TDefault), err.DetailedError)
}

func (c *Context) LogDebug(err *model.AppError) {
	l4g.Debug("api.context.log.error", c.Path, err.Where, err.StatusCode,
		c.RequestId, c.Session.UserId, c.IpAddress, err.SystemMessage(utils.TDefault), err.DetailedError)
}

func (c *Context) SessionRequired() {

	if len(c.Session.UserId) == 0 {
		c.Err = model.NewAppError("", "api.context.session_expired.app_error", nil, "UserRequired", http.StatusUnauthorized)
		return
	}
}

func (c *Context) RemoveSessionCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     model.SESSION_COOKIE_TOKEN,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	userCookie := &http.Cookie{
		Name:   model.SESSION_COOKIE_USER,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}

	http.SetCookie(w, cookie)
	http.SetCookie(w, userCookie)
}

func (c *Context) SetInvalidParam(where string, name string) {
	c.Err = NewInvalidParamError(where, name)
}

func NewInvalidParamError(where string, name string) *model.AppError {
	err := model.NewAppError(where, "api.context.invalid_param.app_error", map[string]interface{}{"Name": name}, "", http.StatusBadRequest)
	return err
}

func (c *Context) SetSiteURLHeader(url string) {
	c.siteURLHeader = strings.TrimRight(url, "/")
}

func (c *Context) GetSiteURLHeader() string {
	return c.siteURLHeader
}

func IsApiCall(r *http.Request) bool {
	return strings.Index(r.URL.Path, "/api/") == 0
}

func Handle404(a *app.App, w http.ResponseWriter, r *http.Request) {
	err := model.NewAppError("Handle404", "api.context.404.app_error", nil, "", http.StatusNotFound)

	l4g.Debug("%v: code=404 ip=%v", r.URL.Path, utils.GetIpAddress(r))

	if IsApiCall(r) {
		w.WriteHeader(err.StatusCode)
		err.DetailedError = "There doesn't appear to be an api call for the url='" + r.URL.Path + "'.  Typo? are you missing a team_id or user_id as part of the url?"
		utils.ReplyApiError(w, r, err)
	} else {
		utils.RenderWebAppError(w, r, err)
	}
}
