package api

import (
	"net/http"
)

func (api *API) InitPlan() {
	api.BaseRoutes.Users.Handle("", api.ApiSessionRequired(getPlan)).Methods("POST")
	api.BaseRoutes.Users.Handle("/record", api.ApiSessionRequired(addPlanRecord)).Methods("POST")
	api.BaseRoutes.Users.Handle("/change", api.ApiSessionRequired(changeUserPlan)).Methods("POST")
}

func getPlan(c *Context, w http.ResponseWriter, r *http.Request) {

}

func addPlanRecord(c *Context, w http.ResponseWriter, r *http.Request) {

}

func changeUserPlan(c *Context, w http.ResponseWriter, r *http.Request) {

}
