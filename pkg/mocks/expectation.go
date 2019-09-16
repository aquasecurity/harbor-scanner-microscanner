package mocks

import "testing"

// Expectation represents an expectation of a method being called and its return values.
type Expectation struct {
	MethodName      string
	Arguments       []interface{}
	ReturnArguments []interface{}
}

// ApplyExpectation applies the specified expectations on a given mock.
func ApplyExpectations(t *testing.T, mock interface{}, expectations ...*Expectation) {
	t.Helper()
	if len(expectations) == 0 || expectations[0] == nil {
		return
	}
	switch v := mock.(type) {
	case *AuthorizerMock:
		m := mock.(*AuthorizerMock)
		for _, e := range expectations {
			m.On(e.MethodName, e.Arguments...).Return(e.ReturnArguments...)
		}
	case *WrapperMock:
		m := mock.(*WrapperMock)
		for _, e := range expectations {
			m.On(e.MethodName, e.Arguments...).Return(e.ReturnArguments...)
		}
	case *TransformerMock:
		m := mock.(*TransformerMock)
		for _, e := range expectations {
			m.On(e.MethodName, e.Arguments...).Return(e.ReturnArguments...)
		}
	case *DataStoreMock:
		m := mock.(*DataStoreMock)
		for _, e := range expectations {
			m.On(e.MethodName, e.Arguments...).Return(e.ReturnArguments...)
		}
	case *JobQueueMock:
		m := mock.(*JobQueueMock)
		for _, e := range expectations {
			m.On(e.MethodName, e.Arguments...).Return(e.ReturnArguments...)
		}
	default:
		t.Fatalf("Unrecognized mock type: %T!", v)
	}
}
