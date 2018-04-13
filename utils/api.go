// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package utils

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/WTHealth/server/model"
)

func CheckOrigin(r *http.Request, allowedOrigins string) bool {
	origin := r.Header.Get("Origin")
	if allowedOrigins == "*" {
		return true
	}
	for _, allowed := range strings.Split(allowedOrigins, " ") {
		if allowed == origin {
			return true
		}
	}
	return false
}

func OriginChecker(allowedOrigins string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return CheckOrigin(r, allowedOrigins)
	}
}

func RenderWebAppError(w http.ResponseWriter, r *http.Request, err *model.AppError) {
	RenderWebError(w, r, err.StatusCode, url.Values{
		"message": []string{err.Message},
	})
}

func RenderWebError(w http.ResponseWriter, r *http.Request, status int, params url.Values) {
	queryString := params.Encode()

	destination := "/error?" + queryString

	if status >= 300 && status < 400 {
		http.Redirect(w, r, destination, status)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	fmt.Fprintln(w, `<!DOCTYPE html><html><head></head>`)
	fmt.Fprintln(w, `<body onload="window.location = '`+template.HTMLEscapeString(template.JSEscapeString(destination))+`'">`)
	fmt.Fprintln(w, `<noscript><meta http-equiv="refresh" content="0; url=`+template.HTMLEscapeString(destination)+`"></noscript>`)
	fmt.Fprintln(w, `<a href="`+template.HTMLEscapeString(destination)+`" style="color: #c0c0c0;">...</a>`)
	fmt.Fprintln(w, `</body></html>`)
}

func ReplyApiError(w http.ResponseWriter, r *http.Request, err *model.AppError) {
	ret, _ := json.Marshal(&model.ApiResult{
		Code: strconv.Itoa(err.StatusCode),
		Desc: err.Message,
		Data: make(map[string]interface{}),
	})

	w.WriteHeader(err.StatusCode)
	w.Write([]byte(ret))
}

func ReplyApiResult(w http.ResponseWriter, r *http.Request, s interface{}) {
	ret, _ := json.Marshal(model.ApiResult{
		Code: "200",
		Desc: "",
		Data: model.ConvertToMap(s),
	})

	w.Write([]byte(ret))
}
