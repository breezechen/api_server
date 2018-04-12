// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"net/http"

	"github.com/WTHealth/server/model"
)

func (a *App) CreateSession(session *model.Session) (*model.Session, *model.AppError) {
	session.Token = ""

	if result := <-a.Srv.Store.Session().Save(session); result.Err != nil {
		return nil, result.Err
	} else {
		return session, nil
	}
}

func (a *App) GetSession(token string) (*model.Session, *model.AppError) {
	if sessionResult := <-a.Srv.Store.Session().Get(token); sessionResult.Err == nil {
		session := sessionResult.Data.(*model.Session)
		return session, nil
	} else  {
		return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token, "Error": ""}, "", http.StatusUnauthorized)
	}
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