package action

import (
	"errors"
	"regexp"
	"strings"
)

const (
	ExecutionModeExternalAuthorized = "external_authorized"
)

var actionTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

var builtInActionTypes = map[string]struct{}{
	"fs.read":          {},
	"fs.write":         {},
	"repo.apply_patch": {},
	"process.exec":     {},
	"net.http_request": {},
	"secrets.checkout": {},
}

func ValidateActionType(actionType string) error {
	actionType = strings.TrimSpace(actionType)
	if actionType == "" {
		return errors.New("action_type is required")
	}
	if !actionTypePattern.MatchString(actionType) {
		return errors.New("action_type has invalid format")
	}
	return nil
}

func IsBuiltInActionType(actionType string) bool {
	_, ok := builtInActionTypes[strings.TrimSpace(actionType)]
	return ok
}
