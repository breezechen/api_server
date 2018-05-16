package model

type AuthCode struct {
	Id       string
	Code     string
	Type     string
	Duration int64
}
