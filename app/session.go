// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/http"

	l4g "github.com/alecthomas/log4go"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
)

func (a *App) CreateSession(session *model.Session) (*model.Session, *model.AppError) {
	session.Token = ""

	if result := <-a.Srv.Store.Session().Save(session); result.Err != nil {
		return nil, result.Err
	} else {
		session := result.Data.(*model.Session)

		a.AddSessionToCache(session)

		return session, nil
	}
}

func (a *App) GetSession(token string) (*model.Session, *model.AppError) {
	var session *model.Session
	if ts, ok := a.sessionCache.Get(token); ok {
		session = ts.(*model.Session)
	}

	if session == nil {
		if sessionResult := <-a.Srv.Store.Session().Get(token); sessionResult.Err == nil {
			session = sessionResult.Data.(*model.Session)
			
			if session != nil {
				if session.Token != token {
					return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token, "Error": ""}, "", http.StatusUnauthorized)
				}

				if !session.IsExpired() {
					a.AddSessionToCache(session)
				}
			}

		} else if sessionResult.Err.StatusCode == http.StatusInternalServerError {
			return nil, sessionResult.Err
		}
	}

	if session == nil || session.IsExpired() {
		return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token}, "", http.StatusUnauthorized)
	}

	return session, nil
}

func (a *App) GetSessionById(sessionId string) (*model.Session, *model.AppError) {
	if result := <-a.Srv.Store.Session().Get(sessionId); result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.Session), nil
	}
}

func (a *App) RevokeAllSessions(userId string) *model.AppError {
	if result := <-a.Srv.Store.Session().GetSessions(userId); result.Err != nil {
		return result.Err
	} else {
		sessions := result.Data.([]*model.Session)
		for _, session := range sessions {
			if result := <-a.Srv.Store.Session().Remove(session.Id); result.Err != nil {
				return result.Err
			}
		}
	}

	return nil
}

func (a *App) RevokeSessionById(sessionId string) *model.AppError {
	if result := <-a.Srv.Store.Session().Get(sessionId); result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return result.Err
	} else {
		return a.RevokeSession(result.Data.(*model.Session))
	}
}

func (a *App) RevokeSession(session *model.Session) *model.AppError {

	if result := <-a.Srv.Store.Session().Remove(session.Id); result.Err != nil {
		return result.Err
	}
	
	return nil
}

func (a *App) AddSessionToCache(session *model.Session) {
	a.sessionCache.AddWithExpiresInSecs(session.Token, session, int64(*a.Config().ServiceSettings.SessionCacheInMinutes*60))
}

func (a *App) SessionCacheLength() int {
	return a.sessionCache.Len()
}

func (a *App) RevokeSessionsForDeviceId(userId string, deviceId string, currentSessionId string) *model.AppError {
	if result := <-a.Srv.Store.Session().GetSessions(userId); result.Err != nil {
		return result.Err
	} else {
		sessions := result.Data.([]*model.Session)
		for _, session := range sessions {
			if session.DeviceId == deviceId && session.Id != currentSessionId {
				l4g.Debug(utils.T("api.user.login.revoking.app_error"), session.Id, userId)
				if err := a.RevokeSession(session); err != nil {
					// Soft error so we still remove the other sessions
					l4g.Error(err.Error())
				}
			}
		}
	}

	return nil
}