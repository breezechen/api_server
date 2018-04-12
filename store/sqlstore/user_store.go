// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package sqlstore

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/store"
)

var (
	USER_SEARCH_TYPE_NAMES_NO_FULL_NAME = []string{"Username", "Nickname"}
	USER_SEARCH_TYPE_NAMES              = []string{"Username", "FirstName", "LastName", "Nickname"}
	USER_SEARCH_TYPE_ALL_NO_FULL_NAME   = []string{"Username", "Nickname", "Email"}
	USER_SEARCH_TYPE_ALL                = []string{"Username", "FirstName", "LastName", "Nickname", "Email"}
)

type SqlUserStore struct {
	SqlStore
}

func NewSqlUserStore(sqlStore SqlStore) store.UserStore {
	us := &SqlUserStore{
		SqlStore: sqlStore,
	}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.User{}, "Users").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("Username").SetMaxSize(64).SetUnique(true)
		table.ColMap("Password").SetMaxSize(128)
		table.ColMap("AuthData").SetMaxSize(128).SetUnique(true)
		table.ColMap("AuthService").SetMaxSize(32)
		table.ColMap("Email").SetMaxSize(128).SetUnique(true)
		table.ColMap("Nickname").SetMaxSize(64)
		table.ColMap("FirstName").SetMaxSize(64)
		table.ColMap("LastName").SetMaxSize(64)
		table.ColMap("Roles").SetMaxSize(256)
		table.ColMap("Props").SetMaxSize(4000)
		table.ColMap("NotifyProps").SetMaxSize(2000)
		table.ColMap("Locale").SetMaxSize(5)
		table.ColMap("MfaSecret").SetMaxSize(128)
		table.ColMap("Position").SetMaxSize(128)
		table.ColMap("Timezone").SetMaxSize(256)
	}

	return us
}

func (us SqlUserStore) CreateIndexesIfNotExists() {
	us.CreateIndexIfNotExists("idx_users_email", "Users", "Email")
	us.CreateIndexIfNotExists("idx_users_update_at", "Users", "UpdateAt")
	us.CreateIndexIfNotExists("idx_users_create_at", "Users", "CreateAt")
	us.CreateIndexIfNotExists("idx_users_delete_at", "Users", "DeleteAt")

	if us.DriverName() == model.DATABASE_DRIVER_POSTGRES {
		us.CreateIndexIfNotExists("idx_users_email_lower", "Users", "lower(Email)")
		us.CreateIndexIfNotExists("idx_users_username_lower", "Users", "lower(Username)")
		us.CreateIndexIfNotExists("idx_users_nickname_lower", "Users", "lower(Nickname)")
		us.CreateIndexIfNotExists("idx_users_firstname_lower", "Users", "lower(FirstName)")
		us.CreateIndexIfNotExists("idx_users_lastname_lower", "Users", "lower(LastName)")
	}

	us.CreateFullTextIndexIfNotExists("idx_users_all_txt", "Users", strings.Join(USER_SEARCH_TYPE_ALL, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_all_no_full_name_txt", "Users", strings.Join(USER_SEARCH_TYPE_ALL_NO_FULL_NAME, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_names_txt", "Users", strings.Join(USER_SEARCH_TYPE_NAMES, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_names_no_full_name_txt", "Users", strings.Join(USER_SEARCH_TYPE_NAMES_NO_FULL_NAME, ", "))
}

func (us SqlUserStore) Save(user *model.User) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if len(user.Id) > 0 {
			result.Err = model.NewAppError("SqlUserStore.Save", "store.sql_user.save.existing.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
			return
		}

		user.PreSave()
		if result.Err = user.IsValid(); result.Err != nil {
			return
		}

		if err := us.GetMaster().Insert(user); err != nil {
			if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
				result.Err = model.NewAppError("SqlUserStore.Save", "store.sql_user.save.email_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
			} else if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
				result.Err = model.NewAppError("SqlUserStore.Save", "store.sql_user.save.username_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
			} else {
				result.Err = model.NewAppError("SqlUserStore.Save", "store.sql_user.save.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
			}
		} else {
			result.Data = user
		}
	})
}

func (us SqlUserStore) Update(user *model.User, trustedUpdateData bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		user.PreUpdate()

		if result.Err = user.IsValid(); result.Err != nil {
			return
		}

		if oldUserResult, err := us.GetMaster().Get(model.User{}, user.Id); err != nil {
			result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.finding.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
		} else if oldUserResult == nil {
			result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.find.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
		} else {
			oldUser := oldUserResult.(*model.User)
			user.CreateAt = oldUser.CreateAt
			user.AuthData = oldUser.AuthData
			user.AuthService = oldUser.AuthService
			user.Password = oldUser.Password
			user.LastPasswordUpdate = oldUser.LastPasswordUpdate
			user.LastPictureUpdate = oldUser.LastPictureUpdate
			user.EmailVerified = oldUser.EmailVerified
			user.FailedAttempts = oldUser.FailedAttempts
			user.MfaSecret = oldUser.MfaSecret
			user.MfaActive = oldUser.MfaActive

			if !trustedUpdateData {
				user.Roles = oldUser.Roles
				user.DeleteAt = oldUser.DeleteAt
			}

			if user.Email != oldUser.Email {
				user.EmailVerified = false
			}

			if user.Username != oldUser.Username {
				user.UpdateMentionKeysFromUsername(oldUser.Username)
			}

			if count, err := us.GetMaster().Update(user); err != nil {
				if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
					result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.email_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
				} else if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
					result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.username_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
				} else {
					result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.updating.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
				}
			} else if count != 1 {
				result.Err = model.NewAppError("SqlUserStore.Update", "store.sql_user.update.app_error", nil, fmt.Sprintf("user_id=%v, count=%v", user.Id, count), http.StatusInternalServerError)
			} else {
				user.Sanitize(map[string]bool{})
				oldUser.Sanitize(map[string]bool{})
				result.Data = [2]*model.User{user, oldUser}
			}
		}
	})
}

func (us SqlUserStore) UpdateLastPictureUpdate(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		curTime := model.GetMillis()

		if _, err := us.GetMaster().Exec("UPDATE Users SET LastPictureUpdate = :Time, UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdateUpdateAt", "store.sql_user.update_last_picture_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdateUpdateAt(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		curTime := model.GetMillis()

		if _, err := us.GetMaster().Exec("UPDATE Users SET UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdateUpdateAt", "store.sql_user.update_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdatePassword(userId, hashedPassword string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		updateAt := model.GetMillis()

		if _, err := us.GetMaster().Exec("UPDATE Users SET Password = :Password, LastPasswordUpdate = :LastPasswordUpdate, UpdateAt = :UpdateAt, AuthData = NULL, AuthService = '', EmailVerified = true, FailedAttempts = 0 WHERE Id = :UserId", map[string]interface{}{"Password": hashedPassword, "LastPasswordUpdate": updateAt, "UpdateAt": updateAt, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdatePassword", "store.sql_user.update_password.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdateFailedPasswordAttempts(userId string, attempts int) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.GetMaster().Exec("UPDATE Users SET FailedAttempts = :FailedAttempts WHERE Id = :UserId", map[string]interface{}{"FailedAttempts": attempts, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdateFailedPasswordAttempts", "store.sql_user.update_failed_pwd_attempts.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdateAuthData(userId string, service string, authData *string, email string, resetMfa bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		email = strings.ToLower(email)

		updateAt := model.GetMillis()

		query := `
			UPDATE
			     Users
			SET
			     Password = '',
			     LastPasswordUpdate = :LastPasswordUpdate,
			     UpdateAt = :UpdateAt,
			     FailedAttempts = 0,
			     AuthService = :AuthService,
			     AuthData = :AuthData`

		if len(email) != 0 {
			query += ", Email = :Email"
		}

		if resetMfa {
			query += ", MfaActive = false, MfaSecret = ''"
		}

		query += " WHERE Id = :UserId"

		if _, err := us.GetMaster().Exec(query, map[string]interface{}{"LastPasswordUpdate": updateAt, "UpdateAt": updateAt, "UserId": userId, "AuthService": service, "AuthData": authData, "Email": email}); err != nil {
			if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique", "AuthData", "users_authdata_key"}) {
				result.Err = model.NewAppError("SqlUserStore.UpdateAuthData", "store.sql_user.update_auth_data.email_exists.app_error", map[string]interface{}{"Service": service, "Email": email}, "user_id="+userId+", "+err.Error(), http.StatusBadRequest)
			} else {
				result.Err = model.NewAppError("SqlUserStore.UpdateAuthData", "store.sql_user.update_auth_data.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
			}
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdateMfaSecret(userId, secret string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		updateAt := model.GetMillis()

		if _, err := us.GetMaster().Exec("UPDATE Users SET MfaSecret = :Secret, UpdateAt = :UpdateAt WHERE Id = :UserId", map[string]interface{}{"Secret": secret, "UpdateAt": updateAt, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdateMfaSecret", "store.sql_user.update_mfa_secret.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) UpdateMfaActive(userId string, active bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		updateAt := model.GetMillis()

		if _, err := us.GetMaster().Exec("UPDATE Users SET MfaActive = :Active, UpdateAt = :UpdateAt WHERE Id = :UserId", map[string]interface{}{"Active": active, "UpdateAt": updateAt, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.UpdateMfaActive", "store.sql_user.update_mfa_active.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us SqlUserStore) Get(id string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if obj, err := us.GetReplica().Get(model.User{}, id); err != nil {
			result.Err = model.NewAppError("SqlUserStore.Get", "store.sql_user.get.app_error", nil, "user_id="+id+", "+err.Error(), http.StatusInternalServerError)
		} else if obj == nil {
			result.Err = model.NewAppError("SqlUserStore.Get", store.MISSING_ACCOUNT_ERROR, nil, "user_id="+id, http.StatusNotFound)
		} else {
			result.Data = obj.(*model.User)
		}
	})
}

func (us SqlUserStore) GetAll() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var data []*model.User
		if _, err := us.GetReplica().Select(&data, "SELECT * FROM Users"); err != nil {
			result.Err = model.NewAppError("SqlUserStore.GetAll", "store.sql_user.get.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = data
	})
}

func (us SqlUserStore) GetByEmail(email string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		email = strings.ToLower(email)

		user := model.User{}

		if err := us.GetReplica().SelectOne(&user, "SELECT * FROM Users WHERE Email = :Email", map[string]interface{}{"Email": email}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.GetByEmail", store.MISSING_ACCOUNT_ERROR, nil, "email="+email+", "+err.Error(), http.StatusInternalServerError)
		}

		result.Data = &user
	})
}

func (us SqlUserStore) GetByUsername(username string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		user := model.User{}

		if err := us.GetReplica().SelectOne(&user, "SELECT * FROM Users WHERE Username = :Username", map[string]interface{}{"Username": username}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.GetByUsername", "store.sql_user.get_by_username.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = &user
	})
}

func (us SqlUserStore) GetForLogin(loginId string, allowSignInWithUsername, allowSignInWithEmail bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		params := map[string]interface{}{
			"LoginId":                 loginId,
			"AllowSignInWithUsername": allowSignInWithUsername,
			"AllowSignInWithEmail":    allowSignInWithEmail,
		}

		users := []*model.User{}
		if _, err := us.GetReplica().Select(
			&users,
			`SELECT
				*
			FROM
				Users
			WHERE
				(:AllowSignInWithUsername AND Username = :LoginId)
				OR (:AllowSignInWithEmail AND Email = :LoginId)`,
			params); err != nil {
			result.Err = model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else if len(users) == 1 {
			result.Data = users[0]
		} else if len(users) > 1 {
			result.Err = model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.multiple_users", nil, "", http.StatusInternalServerError)
		} else {
			result.Err = model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, "", http.StatusInternalServerError)
		}
	})
}

func (us SqlUserStore) VerifyEmail(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.GetMaster().Exec("UPDATE Users SET EmailVerified = true WHERE Id = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.VerifyEmail", "store.sql_user.verify_email.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
		}

		result.Data = userId
	})
}

func (us SqlUserStore) GetTotalUsersCount() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if count, err := us.GetReplica().SelectInt("SELECT COUNT(Id) FROM Users"); err != nil {
			result.Err = model.NewAppError("SqlUserStore.GetTotalUsersCount", "store.sql_user.get_total_users_count.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = count
		}
	})
}

func (us SqlUserStore) PermanentDelete(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.GetMaster().Exec("DELETE FROM Users WHERE Id = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.PermanentDelete", "store.sql_user.permanent_delete.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
		}
	})
}

func (us SqlUserStore) AnalyticsActiveCount(timePeriod int64) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		time := model.GetMillis() - timePeriod

		query := "SELECT COUNT(*) FROM Status WHERE LastActivityAt > :Time"

		v, err := us.GetReplica().SelectInt(query, map[string]interface{}{"Time": time})
		if err != nil {
			result.Err = model.NewAppError("SqlUserStore.AnalyticsDailyActiveUsers", "store.sql_user.analytics_daily_active_users.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = v
		}
	})
}

var escapeLikeSearchChar = []string{
	"%",
	"_",
}

var ignoreLikeSearchChar = []string{
	"*",
}

var spaceFulltextSearchChar = []string{
	"<",
	">",
	"+",
	"-",
	"(",
	")",
	"~",
	":",
	"*",
	"\"",
	"!",
	"@",
}

func generateSearchQuery(searchQuery string, terms []string, fields []string, parameters map[string]interface{}, isPostgreSQL bool) string {
	searchTerms := []string{}
	for i, term := range terms {
		searchFields := []string{}
		for _, field := range fields {
			if isPostgreSQL {
				searchFields = append(searchFields, fmt.Sprintf("lower(%s) LIKE lower(%s) escape '*' ", field, fmt.Sprintf(":Term%d", i)))
			} else {
				searchFields = append(searchFields, fmt.Sprintf("%s LIKE %s escape '*' ", field, fmt.Sprintf(":Term%d", i)))
			}
		}
		searchTerms = append(searchTerms, fmt.Sprintf("(%s)", strings.Join(searchFields, " OR ")))
		parameters[fmt.Sprintf("Term%d", i)] = fmt.Sprintf("%s%%", term)
	}

	searchClause := strings.Join(searchTerms, " AND ")
	return strings.Replace(searchQuery, "SEARCH_CLAUSE", fmt.Sprintf(" AND %s ", searchClause), 1)
}

func (us SqlUserStore) performSearch(searchQuery string, term string, options map[string]bool, parameters map[string]interface{}) store.StoreResult {
	result := store.StoreResult{}

	// These chars must be removed from the like query.
	for _, c := range ignoreLikeSearchChar {
		term = strings.Replace(term, c, "", -1)
	}

	// These chars must be escaped in the like query.
	for _, c := range escapeLikeSearchChar {
		term = strings.Replace(term, c, "*"+c, -1)
	}

	searchType := USER_SEARCH_TYPE_ALL
	if ok := options[store.USER_SEARCH_OPTION_NAMES_ONLY]; ok {
		searchType = USER_SEARCH_TYPE_NAMES
	} else if ok = options[store.USER_SEARCH_OPTION_NAMES_ONLY_NO_FULL_NAME]; ok {
		searchType = USER_SEARCH_TYPE_NAMES_NO_FULL_NAME
	} else if ok = options[store.USER_SEARCH_OPTION_ALL_NO_FULL_NAME]; ok {
		searchType = USER_SEARCH_TYPE_ALL_NO_FULL_NAME
	}

	if ok := options[store.USER_SEARCH_OPTION_ALLOW_INACTIVE]; ok {
		searchQuery = strings.Replace(searchQuery, "INACTIVE_CLAUSE", "", 1)
	} else {
		searchQuery = strings.Replace(searchQuery, "INACTIVE_CLAUSE", "AND Users.DeleteAt = 0", 1)
	}

	if strings.TrimSpace(term) == "" {
		searchQuery = strings.Replace(searchQuery, "SEARCH_CLAUSE", "", 1)
	} else {
		isPostgreSQL := us.DriverName() == model.DATABASE_DRIVER_POSTGRES
		searchQuery = generateSearchQuery(searchQuery, strings.Fields(term), searchType, parameters, isPostgreSQL)
	}

	var users []*model.User

	if _, err := us.GetReplica().Select(&users, searchQuery, parameters); err != nil {
		result.Err = model.NewAppError("SqlUserStore.Search", "store.sql_user.search.app_error", nil,
			fmt.Sprintf("term=%v, search_type=%v, %v", term, searchType, err.Error()), http.StatusInternalServerError)
	} else {
		for _, u := range users {
			u.Sanitize(map[string]bool{})
		}

		result.Data = users
	}

	return result
}

func (us SqlUserStore) AnalyticsGetInactiveUsersCount() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if count, err := us.GetReplica().SelectInt("SELECT COUNT(Id) FROM Users WHERE DeleteAt > 0"); err != nil {
			result.Err = model.NewAppError("SqlUserStore.AnalyticsGetInactiveUsersCount", "store.sql_user.analytics_get_inactive_users_count.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = count
		}
	})
}

func (us SqlUserStore) AnalyticsGetSystemAdminCount() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if count, err := us.GetReplica().SelectInt("SELECT count(*) FROM Users WHERE Roles LIKE :Roles and DeleteAt = 0", map[string]interface{}{"Roles": "%system_admin%"}); err != nil {
			result.Err = model.NewAppError("SqlUserStore.AnalyticsGetSystemAdminCount", "store.sql_user.analytics_get_system_admin_count.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = count
		}
	})
}