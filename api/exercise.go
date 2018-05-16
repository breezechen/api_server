package api

import (
	"net/http"

	"github.com/WTHealth/server/utils"
)

func (api *API) InitExercise() {
	api.BaseRoutes.Exercise.Handle("", api.ApiSessionRequired(getExercise)).Methods("POST")
	api.BaseRoutes.Exercise.Handle("/record", api.ApiSessionRequired(addExerciseRecord)).Methods("POST")
}

func getExercise(c *Context, w http.ResponseWriter, r *http.Request) {
	ret := make(map[string]interface{})

	ret["userId"] = c.Session.UserId
	ret["totalConsume"] = "125"
	ret["totalTime"] = "60"
	ret["coins"] = "2"
	ret["rate"] = "0.15"
	ret["level"] = "1"

	utils.ReplyApiResult(w, r, ret)
}

func addExerciseRecord(c *Context, w http.ResponseWriter, r *http.Request) {
	ret := make(map[string]interface{})
	utils.ReplyApiResult(w, r, ret)
}
