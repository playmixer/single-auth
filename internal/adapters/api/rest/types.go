package rest

import "encoding/json"

type tUser struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Payload struct {
	Link   string
	Params string
}

func (p Payload) MarshalBinary() ([]byte, error) {
	return json.Marshal(p)
}

func (p *Payload) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, p)
}
