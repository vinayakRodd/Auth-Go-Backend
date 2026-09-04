package repository

import "errors"

// This is the correct way to define multiple error variables in a block
var (
    ErrEmailAlreadyExists = errors.New("email already exists")
    ErrNotFound           = errors.New("record not found")
	ErrInvalidInput       = errors.New("invalid input provided")
)