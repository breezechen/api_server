package api

import (
	"net/http"

	"github.com/WTHealth/server/utils"
)

func (api *API) InitPlan() {
	api.BaseRoutes.Plan.Handle("", api.ApiSessionRequired(getPlan)).Methods("POST")
	api.BaseRoutes.Plan.Handle("/record", api.ApiSessionRequired(addPlanRecord)).Methods("POST")
	api.BaseRoutes.Plan.Handle("/change", api.ApiSessionRequired(changeUserPlan)).Methods("POST")
}

func getPlan(c *Context, w http.ResponseWriter, r *http.Request) {
	ret := make(map[string]interface{})
	var arr []map[string]interface{}
	item := make(map[string]interface{})
	item["exerciseName"] = "exerciseName"
	item["exerciseId"] = "exerciseId"
	item["description"] = "description"
	item["unit"] = "min"
	item["unitConsume"] = "100"

	arr = append(arr, item)
	ret["exercise"] = arr

	utils.ReplyApiResult(w, r, ret)
}

func addPlanRecord(c *Context, w http.ResponseWriter, r *http.Request) {
	ret := make(map[string]interface{})
	utils.ReplyApiResult(w, r, ret)
}

func changeUserPlan(c *Context, w http.ResponseWriter, r *http.Request) {
	// props := model.MapFromJson(r.Body)
	ret := make(map[string]interface{})
	utils.ReplyApiResult(w, r, ret)
}
