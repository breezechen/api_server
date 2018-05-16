// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api

import (
	"net/http"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
)

func (api *API) InitUser() {
	api.BaseRoutes.Users.Handle("/create", api.ApiHandler(createUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("/isTaken", api.ApiHandler(isTaken)).Methods("POST")
	api.BaseRoutes.Users.Handle("/login", api.ApiHandler(login)).Methods("POST")
	api.BaseRoutes.Users.Handle("/logout", api.ApiSessionRequired(logout)).Methods("POST")
	api.BaseRoutes.Users.Handle("", api.ApiSessionRequired(getUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("/update", api.ApiSessionRequired(updateUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("/authCode", api.ApiHandler(genAuthCode)).Methods("POST")
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

	utils.ReplyApiResult(w, r, ruser)
}

func isTaken(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)

	username := props["username"]
	email := props["email"]
	phoneNumber := props["phoneNumber"]

	ret := model.UserIsTaken{
		Username:    "",
		Email:       "",
		PhoneNumber: "",
	}
	if len(username) != 0 {
		_, err := c.App.GetUserByUsername(username)
		if err == nil {
			ret.Username = "true"
		} else {
			ret.Username = "false"
		}
	}
	if len(email) != 0 {
		_, err := c.App.GetUserByEmail(email)
		if err == nil {
			ret.Email = "true"
		} else {
			ret.Email = "false"
		}
	}
	if len(phoneNumber) != 0 {
		_, err := c.App.GetUserByPhoneNumber(phoneNumber)
		if err == nil {
			ret.PhoneNumber = "true"
		} else {
			ret.PhoneNumber = "false"
		}
	}

	utils.ReplyApiResult(w, r, ret)
}

func login(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)

	id := props["id"]
	loginId := props["loginId"]
	password := props["password"]
	deviceId := props["deviceId"]
	// authSessionId := props["authSessionId"]
	authCode := props["authCode"]
	// mfaToken := props["token"]

	user, err := c.App.AuthenticateUserForLogin(id, loginId, password, authCode, deviceId)
	if err != nil {
		c.Err = err
		return
	}

	doLogin(c, w, r, user, deviceId)
	if c.Err != nil {
		return
	}

	user.Sanitize(map[string]bool{})
	user.Token = c.Session.Token

	utils.ReplyApiResult(w, r, user)
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
	data := make(map[string]interface{})
	data["userId"] = c.Session.UserId

	Logout(c, w, r)
	if c.Err == nil {
		utils.ReplyApiResult(w, r, data)
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

func getUser(c *Context, w http.ResponseWriter, r *http.Request) {
	user, err := c.App.GetUser(c.Session.UserId)
	if err != nil {
		c.Err = err
		return
	}

	ret := make(map[string]interface{})
	ret["userId"] = user.Id
	ret["gender"] = "unknown"
	ret["birthday"] = "1995年9月30日"
	ret["city"] = user.Position
	ret["height"] = "175"
	ret["rank"] = "noob"
	ret["goal"] = "loseWeight"
	ret["recommend"] = []string{""}
	ret["weight"] = "60"
	ret["level"] = "0"
	ret["name"] = user.FirstName + " " + user.LastName

	utils.ReplyApiResult(w, r, ret)
}

func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)
	name := props["name"]
	gender := props["gender"]
	birthday := props["birthday"]
	city := props["city"]
	height := props["height"]
	rank := props["rank"]
	goal := props["goal"]
	recommend := props["recommend"]
	weight := props["weight"]

	ret := make(map[string]interface{})
	ret["name"] = name
	ret["gender"] = gender
	ret["birthday"] = birthday
	ret["city"] = city
	ret["height"] = height
	ret["rank"] = rank
	ret["goal"] = goal
	ret["recommend"] = recommend
	ret["weight"] = weight

	utils.ReplyApiResult(w, r, ret)
}

func genAuthCode(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)
	phoneNo := props["phoneNumber"]
	authCode, _ := c.App.GenAuthCode(phoneNo)

	ret := make(map[string]interface{})
	ret["authSessionId"] = authCode.Id
	ret["authCode"] = authCode.Code

	utils.ReplyApiResult(w, r, ret)
}
