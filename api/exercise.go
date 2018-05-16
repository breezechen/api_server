package api

import (
	"net/http"
)

func (api *API) InitExercise() {
	api.BaseRoutes.Users.Handle("", api.ApiSessionRequired(getExercise)).Methods("POST")
	api.BaseRoutes.Users.Handle("/record", api.ApiSessionRequired(addExerciseRecord)).Methods("POST")
}

func getExercise(c *Context, w http.ResponseWriter, r *http.Request) {

}

func addExerciseRecord(c *Context, w http.ResponseWriter, r *http.Request) {

}
