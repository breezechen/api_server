// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"net/http"
	
	"github.com/WTHealth/server/model"

)

func (api *API) InitUser() {
	api.BaseRoutes.Users.Handle("/create", api.ApiAppHandler(createUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("/login", api.ApiAppHandler(login)).Methods("POST")
	api.BaseRoutes.Users.Handle("/logout", api.ApiAppHandler(logout)).Methods("POST")
}

func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	user := model.UserFromJson(r.Body)

	if user == nil {
		c.SetInvalidParam("createUser", "user")
		return
	}

	ruser, err := c.App.CreateUserFromSignup(user)

	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(ruser.ToJson()))
}

func login(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)

	id := props["id"]
	loginId := props["loginId"]
	password := props["password"]
	deviceId := props["deviceId"]
	mfaToken := props["token"]

	user, err := c.App.AuthenticateUserForLogin(id, loginId, password, mfaToken, deviceId)
	if err != nil {
		c.Err = err
		return
	}

	doLogin(c, w, r, user, deviceId)
	if c.Err != nil {
		return
	}

	user.Sanitize(map[string]bool{})

	w.Write([]byte(user.ToJson()))
}

// User MUST be authenticated completely before calling Login
func doLogin(c *Context, w http.ResponseWriter, r *http.Request, user *model.User, deviceId string) {
	session, err := c.App.DoLogin(w, r, user, deviceId)
	if err != nil {
		c.Err = err
		return
	}

	c.Session = *session
}

func logout(c *Context, w http.ResponseWriter, r *http.Request) {
	data := make(map[string]string)
	data["user_id"] = c.Session.UserId

	Logout(c, w, r)
	if c.Err == nil {
		w.Write([]byte(model.MapToJson(data)))
	}
}

func Logout(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RemoveSessionCookie(w, r)
	if c.Session.Id != "" {
		if err := c.App.RevokeSessionById(c.Session.Id); err != nil {
			c.Err = err
			return
		}
	}
}