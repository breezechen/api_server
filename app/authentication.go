// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/http"
	"strings"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
)

type TokenLocation int

const (
	TokenLocationNotFound = iota
	TokenLocationHeader
	TokenLocationCookie
	TokenLocationQueryString
)

func (tl TokenLocation) String() string {
	switch tl {
	case TokenLocationNotFound:
		return "Not Found"
	case TokenLocationHeader:
		return "Header"
	case TokenLocationCookie:
		return "Cookie"
	case TokenLocationQueryString:
		return "QueryString"
	default:
		return "Unknown"
	}
}

func (a *App) IsPasswordValid(password string) *model.AppError {
	return utils.IsPasswordValid(password)
}

func (a *App) CheckPasswordAndAllCriteria(user *model.User, password string, mfaToken string) *model.AppError {
	if err := a.CheckUserPreflightAuthenticationCriteria(user, mfaToken); err != nil {
		return err
	}

	if len(mfaToken) > 0 {
		phoneNo := user.PhoneNumber
		res, ok := a.sessionCache.Get(phoneNo)
		if ok {
			authCode := res.(model.AuthCode)
			if authCode.Code == mfaToken {
				return nil
			}
		}
		return model.NewAppError("checkUserPassword", "api.user.check_user_password.invalid.auth_code", nil, "user_id="+user.Id, http.StatusUnauthorized)
	}

	if err := a.checkUserPassword(user, password); err != nil {
		return err
	}

	return nil
}

// This to be used for places we check the users password when they are already logged in
func (a *App) doubleCheckPassword(user *model.User, password string) *model.AppError {
	if err := checkUserLoginAttempts(user, *a.Config().ServiceSettings.MaximumLoginAttempts); err != nil {
		return err
	}

	if err := a.checkUserPassword(user, password); err != nil {
		return err
	}

	return nil
}

func (a *App) checkUserPassword(user *model.User, password string) *model.AppError {
	if !model.ComparePassword(user.Password, password) {
		if result := <-a.Srv.Store.User().UpdateFailedPasswordAttempts(user.Id, user.FailedAttempts+1); result.Err != nil {
			return result.Err
		}

		return model.NewAppError("checkUserPassword", "api.user.check_user_password.invalid.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	} else {
		if result := <-a.Srv.Store.User().UpdateFailedPasswordAttempts(user.Id, 0); result.Err != nil {
			return result.Err
		}

		return nil
	}
}

func (a *App) CheckUserAllAuthenticationCriteria(user *model.User, mfaToken string) *model.AppError {
	if err := a.CheckUserPreflightAuthenticationCriteria(user, mfaToken); err != nil {
		return err
	}

	return nil
}

func (a *App) CheckUserPreflightAuthenticationCriteria(user *model.User, mfaToken string) *model.AppError {

	if err := checkUserNotDisabled(user); err != nil {
		return err
	}

	if err := checkUserLoginAttempts(user, *a.Config().ServiceSettings.MaximumLoginAttempts); err != nil {
		return err
	}

	return nil
}

func checkUserLoginAttempts(user *model.User, max int) *model.AppError {
	if user.FailedAttempts >= max {
		return model.NewAppError("checkUserLoginAttempts", "api.user.check_user_login_attempts.too_many.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	}

	return nil
}

func checkUserNotDisabled(user *model.User) *model.AppError {
	if user.DeleteAt > 0 {
		return model.NewAppError("Login", "api.user.login.inactive.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	}
	return nil
}

func (a *App) authenticateUser(user *model.User, password, mfaToken string) (*model.User, *model.AppError) {
	if err := a.CheckPasswordAndAllCriteria(user, password, mfaToken); err != nil {
		err.StatusCode = http.StatusUnauthorized
		return user, err
	} else {
		return user, nil
	}
}

func ParseAuthTokenFromRequest(r *http.Request) (string, TokenLocation) {
	token := r.Header.Get(model.HEADER_TOKEN)
	if len(token) == 26 {
		return token, TokenLocationHeader
	}

	authHeader := r.Header.Get(model.HEADER_AUTH)
	if len(authHeader) > 6 && strings.ToUpper(authHeader[0:6]) == model.HEADER_BEARER {
		// Default session token
		return authHeader[7:], TokenLocationHeader
	} else if len(authHeader) > 5 && strings.ToLower(authHeader[0:5]) == model.HEADER_TOKEN {
		// OAuth token
		return authHeader[6:], TokenLocationHeader
	}

	// Attempt to parse the token from the cookie
	if cookie, err := r.Cookie(model.SESSION_COOKIE_TOKEN); err == nil {
		return cookie.Value, TokenLocationCookie
	}

	// Attempt to parse token out of the query string
	if token = r.URL.Query().Get("access_token"); token != "" {
		return token, TokenLocationQueryString
	}

	return "", TokenLocationNotFound
}
