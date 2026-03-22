package sdk

import (
	"context"
	"errors"
)

type ActionBuilder[T any] func(T) (ActionRequest, error)

type Executor[T any, R any] func(context.Context, T) (R, error)

type ResourceMapper[T any] func(T) (string, error)

type ParamsMapper[T any] func(T) (map[string]any, error)

type ExternalReportBuilder[T any, R any] func(input T, result R, decision DecisionResponse) (ExternalReportRequest, error)

type GuardResult[R any] struct {
	DecisionResponse DecisionResponse
	Executed         bool
	Value            R
}

func (r GuardResult[R]) IsAllowed() bool {
	return r.DecisionResponse.IsAllowed()
}

func (r GuardResult[R]) IsDenied() bool {
	return r.DecisionResponse.IsDenied()
}

func (r GuardResult[R]) RequiresApproval() bool {
	return r.DecisionResponse.RequiresApproval()
}

type GuardedFunction[T any, R any] struct {
	client  *Client
	build   ActionBuilder[T]
	execute Executor[T, R]
}

func NewGuardedFunction[T any, R any](client *Client, build ActionBuilder[T], execute Executor[T, R]) (GuardedFunction[T, R], error) {
	if client == nil {
		return GuardedFunction[T, R]{}, errors.New("client is required")
	}
	if build == nil {
		return GuardedFunction[T, R]{}, errors.New("build is required")
	}
	if execute == nil {
		return GuardedFunction[T, R]{}, errors.New("execute is required")
	}
	return GuardedFunction[T, R]{
		client:  client,
		build:   build,
		execute: execute,
	}, nil
}

func (g GuardedFunction[T, R]) Invoke(ctx context.Context, input T) (GuardResult[R], error) {
	var zero GuardResult[R]
	req, err := g.build(input)
	if err != nil {
		return zero, err
	}
	decision, err := g.client.RunAction(ctx, req)
	if err != nil {
		return zero, err
	}
	result := GuardResult[R]{DecisionResponse: decision}
	if !decision.IsAllowed() {
		return result, nil
	}
	value, err := g.execute(ctx, input)
	if err != nil {
		return result, err
	}
	result.Executed = true
	result.Value = value
	return result, nil
}

func (g GuardedFunction[T, R]) InvokeAndReport(ctx context.Context, input T, buildReport ExternalReportBuilder[T, R]) (GuardResult[R], error) {
	result, err := g.Invoke(ctx, input)
	if err != nil {
		return result, err
	}
	if !result.Executed || buildReport == nil {
		return result, nil
	}
	report, err := buildReport(input, result.Value, result.DecisionResponse)
	if err != nil {
		return result, err
	}
	if _, err := g.client.ReportExternalOutcome(ctx, report); err != nil {
		return result, err
	}
	return result, nil
}

func NewGuardedHTTPTool[T any, R any](client *Client, resource ResourceMapper[T], params ParamsMapper[T], execute Executor[T, R]) (GuardedFunction[T, R], error) {
	return NewGuardedFunction(client, buildAction("net.http_request", resource, params), execute)
}

func NewGuardedSubprocessTool[T any, R any](client *Client, resource ResourceMapper[T], params ParamsMapper[T], execute Executor[T, R]) (GuardedFunction[T, R], error) {
	return NewGuardedFunction(client, buildAction("process.exec", resource, params), execute)
}

func NewGuardedFileReadTool[T any, R any](client *Client, resource ResourceMapper[T], params ParamsMapper[T], execute Executor[T, R]) (GuardedFunction[T, R], error) {
	return NewGuardedFunction(client, buildAction("fs.read", resource, params), execute)
}

func NewGuardedFileWriteTool[T any, R any](client *Client, resource ResourceMapper[T], params ParamsMapper[T], execute Executor[T, R]) (GuardedFunction[T, R], error) {
	return NewGuardedFunction(client, buildAction("fs.write", resource, params), execute)
}

func buildAction[T any](actionType string, resource ResourceMapper[T], params ParamsMapper[T]) ActionBuilder[T] {
	return func(input T) (ActionRequest, error) {
		if resource == nil {
			return ActionRequest{}, errors.New("resource mapper is required")
		}
		if params == nil {
			return ActionRequest{}, errors.New("params mapper is required")
		}
		mappedResource, err := resource(input)
		if err != nil {
			return ActionRequest{}, err
		}
		mappedParams, err := params(input)
		if err != nil {
			return ActionRequest{}, err
		}
		return NewActionRequest(actionType, mappedResource, mappedParams), nil
	}
}
