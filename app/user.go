// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/http"

	l4g "github.com/alecthomas/log4go"

	"github.com/WTHealth/server/model"
)

const (
	TOKEN_TYPE_PASSWORD_RECOVERY  = "password_recovery"
	TOKEN_TYPE_VERIFY_EMAIL       = "verify_email"
	PASSWORD_RECOVER_EXPIRY_TIME  = 1000 * 60 * 60 // 1 hour
	IMAGE_PROFILE_PIXEL_DIMENSION = 128
)

func (a *App) CreateUserFromSignup(user *model.User) (*model.User, *model.AppError) {
	if err := a.IsUserSignUpAllowed(); err != nil {
		return nil, err
	}

	user.EmailVerified = false

	ruser, err := a.CreateUser(user)
	if err != nil {
		return nil, err
	}

	return ruser, nil
}

func (a *App) IsUserSignUpAllowed() *model.AppError {
	return nil
}

func (a *App) IsFirstUserAccount() bool {
	if cr := <-a.Srv.Store.User().GetTotalUsersCount(); cr.Err != nil {
		l4g.Error(cr.Err)
		return false
	} else {
		count := cr.Data.(int64)
		if count <= 0 {
			return true
		} else {
			return false
		}
	}
}

func (a *App) CreateUser(user *model.User) (*model.User, *model.AppError) {
	if ruser, err := a.createUser(user); err != nil {
		return nil, err
	} else {
		return ruser, nil
	}
}

func (a *App) createUser(user *model.User) (*model.User, *model.AppError) {
	user.MakeNonNil()

	if err := a.IsPasswordValid(user.Password); user.AuthService == "" && err != nil {
		return nil, err
	}

	if result := <-a.Srv.Store.User().Save(user); result.Err != nil {
		l4g.Error("api.user.create_user.save.error", result.Err)
		return nil, result.Err
	} else {
		ruser := result.Data.(*model.User)
		ruser.Sanitize(map[string]bool{})

		return ruser, nil
	}
}

func (a *App) IsValidUsername(name string) bool {

	if !model.IsValidUsername(name) {
		return false
	}

	_, err := a.GetUserByUsername(name)
	if err == nil {
		return false
	}
	return true
}

func (a *App) IsValidEmail(email string) bool {

	if !model.IsValidEmail(email) {
		return false
	}

	_, err := a.GetUserByEmail(email)
	if err == nil {
		return false
	}

	return true
}

func (a *App) IsValidPhoneNumber(phoneNumber string) bool {

	if !model.IsValidPhoneNumber(phoneNumber) {
		return false
	}

	_, err := a.GetUserByPhoneNumber(phoneNumber)
	if err == nil {
		return false
	}

	return true
}

func (a *App) GetUser(userId string) (*model.User, *model.AppError) {
	if result := <-a.Srv.Store.User().Get(userId); result.Err != nil {
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserByUsername(username string) (*model.User, *model.AppError) {
	if result := <-a.Srv.Store.User().GetByUsername(username); result.Err != nil && result.Err.Id == "store.sql_user.get_by_username.app_error" {
		result.Err.StatusCode = http.StatusNotFound
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserByEmail(email string) (*model.User, *model.AppError) {

	if result := <-a.Srv.Store.User().GetByEmail(email); result.Err != nil && result.Err.Id == "store.sql_user.missing_account.const" {
		result.Err.StatusCode = http.StatusNotFound
		return nil, result.Err
	} else if result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserByPhoneNumber(phoneNumber string) (*model.User, *model.AppError) {

	if result := <-a.Srv.Store.User().GetByPhoneNumber(phoneNumber); result.Err != nil && result.Err.Id == "store.sql_user.missing_account.const" {
		result.Err.StatusCode = http.StatusNotFound
		return nil, result.Err
	} else if result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserForLogin(loginId string) (*model.User, *model.AppError) {
	if result := <-a.Srv.Store.User().GetForLogin(
		loginId, true, true, true); result.Err != nil && result.Err.Id == "store.sql_user.get_for_login.multiple_users" {
		// don't fall back to LDAP in this case since we already know there's an LDAP user, but that it shouldn't work
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else if result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) UpdateActive(user *model.User, active bool) (*model.User, *model.AppError) {
	if active {
		user.DeleteAt = 0
	} else {
		user.DeleteAt = model.GetMillis()
	}

	if result := <-a.Srv.Store.User().Update(user, true); result.Err != nil {
		return nil, result.Err
	} else {
		if user.DeleteAt > 0 {
			if err := a.RevokeAllSessions(user.Id); err != nil {
				return nil, err
			}
		}

		ruser := result.Data.([2]*model.User)[0]
		options := a.Config().GetSanitizeOptions()
		options["passwordupdate"] = false
		ruser.Sanitize(options)

		return ruser, nil
	}
}

func (a *App) SanitizeProfile(user *model.User, asAdmin bool) {
	options := a.Config().GetSanitizeOptions()
	if asAdmin {
		options["email"] = true
		options["fullname"] = true
		options["authservice"] = true
	}
	user.SanitizeProfile(options)
}

func (a *App) DeleteToken(token *model.Token) *model.AppError {
	if result := <-a.Srv.Store.Token().Delete(token.Token); result.Err != nil {
		return result.Err
	}

	return nil
}

func (a *App) PermanentDeleteUser(user *model.User) *model.AppError {
	if _, err := a.UpdateActive(user, false); err != nil {
		return err
	}

	if result := <-a.Srv.Store.Session().PermanentDeleteSessionsByUser(user.Id); result.Err != nil {
		return result.Err
	}

	if result := <-a.Srv.Store.User().PermanentDelete(user.Id); result.Err != nil {
		return result.Err
	}

	l4g.Warn("api.user.permanent_delete_user.deleted.warn", user.Email, user.Id)

	return nil
}

func (a *App) GenAuthCode(phoneNo string) (*model.AuthCode, *model.AppError) {
	num := model.NewNumberCode(6)
	code := model.AuthCode{
		Id:       phoneNo,
		Code:     num,
		Type:     "sms",
		Duration: 10 * 60,
	}
	res, ok := a.sessionCache.Get(code.Id)
	if !ok {
		a.sessionCache.AddWithExpiresInSecs(code.Id, code, code.Duration)
	} else {
		code = res.(model.AuthCode)
	}
	return &code, nil
}
