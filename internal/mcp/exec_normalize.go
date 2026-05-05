package mcp

import (
	"errors"
	"strings"
	"unicode"
)

func normalizeExecParams(params execParams) (execParams, error) {
	argv, unwrapped, err := unwrapShellWrapperArgv(params.Argv)
	if err != nil {
		return execParams{}, err
	}
	if unwrapped {
		params.Argv = argv
	}
	return params, nil
}

func unwrapShellWrapperArgv(argv []string) ([]string, bool, error) {
	if len(argv) == 0 {
		return nil, false, errors.New("argv is required")
	}
	switch shellRootName(argv[0]) {
	case "pwsh", "powershell":
		return unwrapPowerShellCommand(argv)
	case "cmd":
		return unwrapCmdCommand(argv)
	case "sh", "bash", "dash", "zsh", "fish", "ksh":
		return unwrapPOSIXShellCommand(argv)
	default:
		return argv, false, nil
	}
}

func unwrapPowerShellCommand(argv []string) ([]string, bool, error) {
	for i := 1; i < len(argv); i++ {
		arg := strings.TrimSpace(argv[i])
		lower := strings.ToLower(arg)
		switch lower {
		case "-command", "-c":
			return parseSimpleShellCommand(strings.Join(argv[i+1:], " "))
		case "-noprofile", "-nol", "-nologo", "-noninteractive", "-mta", "-sta":
			continue
		case "-executionpolicy", "-inputformat", "-outputformat", "-workingdirectory":
			i++
			if i >= len(argv) {
				return nil, true, errors.New("unsupported shell wrapper")
			}
		default:
			return nil, true, errors.New("unsupported shell wrapper")
		}
	}
	return nil, true, errors.New("unsupported shell wrapper")
}

func unwrapCmdCommand(argv []string) ([]string, bool, error) {
	if len(argv) < 3 || !strings.EqualFold(argv[1], "/c") {
		return nil, true, errors.New("unsupported shell wrapper")
	}
	return parseSimpleShellCommand(strings.Join(argv[2:], " "))
}

func unwrapPOSIXShellCommand(argv []string) ([]string, bool, error) {
	for i := 1; i < len(argv); i++ {
		if argv[i] == "-c" {
			return parseSimpleShellCommand(strings.Join(argv[i+1:], " "))
		}
		if !strings.HasPrefix(argv[i], "-") {
			return nil, true, errors.New("unsupported shell wrapper")
		}
	}
	return nil, true, errors.New("unsupported shell wrapper")
}

func parseSimpleShellCommand(command string) ([]string, bool, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, true, errors.New("shell command is empty")
	}
	if strings.ContainsAny(command, "\r\n;&|<>`$%!#(){}[]") {
		return nil, true, errors.New("shell command contains unsupported syntax")
	}
	fields, err := splitSimpleCommandFields(command)
	if err != nil {
		return nil, true, err
	}
	if len(fields) == 0 {
		return nil, true, errors.New("shell command is empty")
	}
	return fields, true, nil
}

func splitSimpleCommandFields(command string) ([]string, error) {
	fields := []string{}
	var current strings.Builder
	var quote rune
	for _, r := range command {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
		case unicode.IsSpace(r):
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, errors.New("shell command has unterminated quote")
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields, nil
}

func shellRootName(command string) string {
	command = strings.TrimSpace(command)
	command = strings.ReplaceAll(command, "\\", "/")
	if idx := strings.LastIndex(command, "/"); idx >= 0 {
		command = command[idx+1:]
	}
	command = strings.ToLower(command)
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		command = strings.TrimSuffix(command, suffix)
	}
	return command
}
