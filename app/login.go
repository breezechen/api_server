// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/avct/uasurfer"
	"github.com/WTHealth/server/model"
)

func (a *App) AuthenticateUserForLogin(id, loginId, password, mfaToken, deviceId string) (*model.User, *model.AppError) {
	if len(password) == 0 {
		err := model.NewAppError("AuthenticateUserForLogin", "api.user.login.blank_pwd.app_error", nil, "", http.StatusBadRequest)
		return nil, err
	}

	var user *model.User
	var err *model.AppError

	if len(id) != 0 {
		if user, err = a.GetUser(id); err != nil {
			err.StatusCode = http.StatusBadRequest
			return nil, err
		}
	} else {
		if user, err = a.GetUserForLogin(loginId); err != nil {
			return nil, err
		}
	}

	// and then authenticate them
	if user, err = a.authenticateUser(user, password, mfaToken); err != nil {
		return nil, err
	}

	return user, nil
}

func (a *App) DoLogin(w http.ResponseWriter, r *http.Request, user *model.User, deviceId string) (*model.Session, *model.AppError) {
	session := &model.Session{UserId: user.Id, DeviceId: deviceId}

	maxAge := *a.Config().ServiceSettings.SessionLengthWebInDays * 60 * 60 * 24

	ua := uasurfer.Parse(r.UserAgent())

	plat := ua.OS.Platform.String()
	if plat == "" {
		plat = "unknown"
	}

	os := ua.OS.Name.String()
	if os == "" {
		os = "unknown"
	}

	bname := ua.Browser.Name.String()
	if bname == "" {
		bname = "unknown"
	}

	if strings.Contains(r.UserAgent(), "Mattermost") {
		bname = "Desktop App"
	}

	bversion := ua.Browser.Version

	session.AddProp(model.SESSION_PROP_PLATFORM, plat)
	session.AddProp(model.SESSION_PROP_OS, os)
	session.AddProp(model.SESSION_PROP_BROWSER, fmt.Sprintf("%v/%v", bname, bversion))

	var err *model.AppError
	if session, err = a.CreateSession(session); err != nil {
		err.StatusCode = http.StatusInternalServerError
		return nil, err
	}

	w.Header().Set(model.HEADER_TOKEN, session.Token)

	secure := false
	if GetProtocol(r) == "https" {
		secure = true
	}

	domain := a.GetCookieDomain()
	expiresAt := time.Unix(model.GetMillis()/1000+int64(maxAge), 0)
	sessionCookie := &http.Cookie{
		Name:     model.SESSION_COOKIE_TOKEN,
		Value:    session.Token,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  expiresAt,
		HttpOnly: true,
		Domain:   domain,
		Secure:   secure,
	}

	userCookie := &http.Cookie{
		Name:    model.SESSION_COOKIE_USER,
		Value:   user.Id,
		Path:    "/",
		MaxAge:  maxAge,
		Expires: expiresAt,
		Domain:  domain,
		Secure:  secure,
	}

	http.SetCookie(w, sessionCookie)
	http.SetCookie(w, userCookie)

	return session, nil
}

func GetProtocol(r *http.Request) string {
	if r.Header.Get(model.HEADER_FORWARDED_PROTO) == "https" || r.TLS != nil {
		return "https"
	} else {
		return "http"
	}
}
