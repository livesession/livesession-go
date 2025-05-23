// This file was auto-generated by Fern from our API Definition.

package livesession

import (
	json "encoding/json"
	fmt "fmt"
	internal "go.livesession.io/livesession-go/internal"
)

type AlertDeleted struct {
	// ID of the deleted alert
	AlertId *string `json:"alert_id,omitempty" url:"alert_id,omitempty"`
	// Confirmation that the alert was deleted
	Deleted *bool `json:"deleted,omitempty" url:"deleted,omitempty"`

	extraProperties map[string]interface{}
	rawJSON         json.RawMessage
}

func (a *AlertDeleted) GetAlertId() *string {
	if a == nil {
		return nil
	}
	return a.AlertId
}

func (a *AlertDeleted) GetDeleted() *bool {
	if a == nil {
		return nil
	}
	return a.Deleted
}

func (a *AlertDeleted) GetExtraProperties() map[string]interface{} {
	return a.extraProperties
}

func (a *AlertDeleted) UnmarshalJSON(data []byte) error {
	type unmarshaler AlertDeleted
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*a = AlertDeleted(value)
	extraProperties, err := internal.ExtractExtraProperties(data, *a)
	if err != nil {
		return err
	}
	a.extraProperties = extraProperties
	a.rawJSON = json.RawMessage(data)
	return nil
}

func (a *AlertDeleted) String() string {
	if len(a.rawJSON) > 0 {
		if value, err := internal.StringifyJSON(a.rawJSON); err == nil {
			return value
		}
	}
	if value, err := internal.StringifyJSON(a); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", a)
}

type ErrorResponse struct {
	Error *ErrorResponseError `json:"error,omitempty" url:"error,omitempty"`

	extraProperties map[string]interface{}
	rawJSON         json.RawMessage
}

func (e *ErrorResponse) GetError() *ErrorResponseError {
	if e == nil {
		return nil
	}
	return e.Error
}

func (e *ErrorResponse) GetExtraProperties() map[string]interface{} {
	return e.extraProperties
}

func (e *ErrorResponse) UnmarshalJSON(data []byte) error {
	type unmarshaler ErrorResponse
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*e = ErrorResponse(value)
	extraProperties, err := internal.ExtractExtraProperties(data, *e)
	if err != nil {
		return err
	}
	e.extraProperties = extraProperties
	e.rawJSON = json.RawMessage(data)
	return nil
}

func (e *ErrorResponse) String() string {
	if len(e.rawJSON) > 0 {
		if value, err := internal.StringifyJSON(e.rawJSON); err == nil {
			return value
		}
	}
	if value, err := internal.StringifyJSON(e); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", e)
}

type ErrorResponseError struct {
	// Type of error (e.g., validation_error, authentication_error)
	Type *string `json:"type,omitempty" url:"type,omitempty"`
	// Machine-readable error code
	Code *string `json:"code,omitempty" url:"code,omitempty"`
	// Name of the parameter that caused the error
	Param *string `json:"param,omitempty" url:"param,omitempty"`
	// Human-readable error message
	Message *string `json:"message,omitempty" url:"message,omitempty"`
	// HTTP status code associated with the error
	HttpStatusCode *int `json:"http_status_code,omitempty" url:"http_status_code,omitempty"`
	// Unique identifier for the request that caused the error
	RequestId *string `json:"request_id,omitempty" url:"request_id,omitempty"`

	extraProperties map[string]interface{}
	rawJSON         json.RawMessage
}

func (e *ErrorResponseError) GetType() *string {
	if e == nil {
		return nil
	}
	return e.Type
}

func (e *ErrorResponseError) GetCode() *string {
	if e == nil {
		return nil
	}
	return e.Code
}

func (e *ErrorResponseError) GetParam() *string {
	if e == nil {
		return nil
	}
	return e.Param
}

func (e *ErrorResponseError) GetMessage() *string {
	if e == nil {
		return nil
	}
	return e.Message
}

func (e *ErrorResponseError) GetHttpStatusCode() *int {
	if e == nil {
		return nil
	}
	return e.HttpStatusCode
}

func (e *ErrorResponseError) GetRequestId() *string {
	if e == nil {
		return nil
	}
	return e.RequestId
}

func (e *ErrorResponseError) GetExtraProperties() map[string]interface{} {
	return e.extraProperties
}

func (e *ErrorResponseError) UnmarshalJSON(data []byte) error {
	type unmarshaler ErrorResponseError
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*e = ErrorResponseError(value)
	extraProperties, err := internal.ExtractExtraProperties(data, *e)
	if err != nil {
		return err
	}
	e.extraProperties = extraProperties
	e.rawJSON = json.RawMessage(data)
	return nil
}

func (e *ErrorResponseError) String() string {
	if len(e.rawJSON) > 0 {
		if value, err := internal.StringifyJSON(e.rawJSON); err == nil {
			return value
		}
	}
	if value, err := internal.StringifyJSON(e); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", e)
}

type OauthScope string

const (
	// read user sessions
	OauthScopeUsersSessionsRead OauthScope = "users.sessions:read"
	// read webhooks
	OauthScopeWebhooksRead OauthScope = "webhooks:read"
	// write webhooks
	OauthScopeWebhooksWrite OauthScope = "webhooks:write"
	// read alerts
	OauthScopeAlertsRead OauthScope = "alerts:read"
	// write alerts
	OauthScopeAlertsWrite OauthScope = "alerts:write"
	// read websites
	OauthScopeWebsitesRead OauthScope = "websites:read"
	// write websites
	OauthScopeWebsitesWrite OauthScope = "websites:write"
	// write payment intents
	OauthScopePaymentIntentsWrite OauthScope = "payment_intents:write"
	// confirm payment intents
	OauthScopePaymentIntentsConfirm OauthScope = "payment_intents.confirm"
)

func NewOauthScopeFromString(s string) (OauthScope, error) {
	switch s {
	case "users.sessions:read":
		return OauthScopeUsersSessionsRead, nil
	case "webhooks:read":
		return OauthScopeWebhooksRead, nil
	case "webhooks:write":
		return OauthScopeWebhooksWrite, nil
	case "alerts:read":
		return OauthScopeAlertsRead, nil
	case "alerts:write":
		return OauthScopeAlertsWrite, nil
	case "websites:read":
		return OauthScopeWebsitesRead, nil
	case "websites:write":
		return OauthScopeWebsitesWrite, nil
	case "payment_intents:write":
		return OauthScopePaymentIntentsWrite, nil
	case "payment_intents.confirm":
		return OauthScopePaymentIntentsConfirm, nil
	}
	var t OauthScope
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (o OauthScope) Ptr() *OauthScope {
	return &o
}

// * `TODAY` - Today since midnight
// * `YESTERDAY` - Yesterday since midnight
// * `BEGINNING_OF_WEEK` - Nearest monday since midnight
// * `BEGINNING_OF_MONTH` - 1st of the month since midnight
// * `BEGINNING_OF_PREV_MONTH` - Previous 1st of the month since midnight
// * `TODAY-7DAYS` - Exact 7 days ago since midnight
// * `TODAY-30DAYS` - Exact 30 days ago since midnight
type RelativeDateString string

const (
	RelativeDateStringToday                RelativeDateString = "TODAY"
	RelativeDateStringYesterday            RelativeDateString = "YESTERDAY"
	RelativeDateStringBeginningOfWeek      RelativeDateString = "BEGINNING_OF_WEEK"
	RelativeDateStringBeginningOfMonth     RelativeDateString = "BEGINNING_OF_MONTH"
	RelativeDateStringBeginningOfPrevMonth RelativeDateString = "BEGINNING_OF_PREV_MONTH"
	RelativeDateStringToday7Days           RelativeDateString = "TODAY-7DAYS"
	RelativeDateStringToday30Days          RelativeDateString = "TODAY-30DAYS"
)

func NewRelativeDateStringFromString(s string) (RelativeDateString, error) {
	switch s {
	case "TODAY":
		return RelativeDateStringToday, nil
	case "YESTERDAY":
		return RelativeDateStringYesterday, nil
	case "BEGINNING_OF_WEEK":
		return RelativeDateStringBeginningOfWeek, nil
	case "BEGINNING_OF_MONTH":
		return RelativeDateStringBeginningOfMonth, nil
	case "BEGINNING_OF_PREV_MONTH":
		return RelativeDateStringBeginningOfPrevMonth, nil
	case "TODAY-7DAYS":
		return RelativeDateStringToday7Days, nil
	case "TODAY-30DAYS":
		return RelativeDateStringToday30Days, nil
	}
	var t RelativeDateString
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (r RelativeDateString) Ptr() *RelativeDateString {
	return &r
}

type SessionPageViewLocationData struct {
	// Base URL of the page
	Base *string `json:"base,omitempty" url:"base,omitempty"`
	// Full URL of the page
	Href *string `json:"href,omitempty" url:"href,omitempty"`
	// Origin of the page (protocol + hostname)
	Origin *string `json:"origin,omitempty" url:"origin,omitempty"`
	// URL of the previous page
	Referrer *string `json:"referrer,omitempty" url:"referrer,omitempty"`

	extraProperties map[string]interface{}
	rawJSON         json.RawMessage
}

func (s *SessionPageViewLocationData) GetBase() *string {
	if s == nil {
		return nil
	}
	return s.Base
}

func (s *SessionPageViewLocationData) GetHref() *string {
	if s == nil {
		return nil
	}
	return s.Href
}

func (s *SessionPageViewLocationData) GetOrigin() *string {
	if s == nil {
		return nil
	}
	return s.Origin
}

func (s *SessionPageViewLocationData) GetReferrer() *string {
	if s == nil {
		return nil
	}
	return s.Referrer
}

func (s *SessionPageViewLocationData) GetExtraProperties() map[string]interface{} {
	return s.extraProperties
}

func (s *SessionPageViewLocationData) UnmarshalJSON(data []byte) error {
	type unmarshaler SessionPageViewLocationData
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*s = SessionPageViewLocationData(value)
	extraProperties, err := internal.ExtractExtraProperties(data, *s)
	if err != nil {
		return err
	}
	s.extraProperties = extraProperties
	s.rawJSON = json.RawMessage(data)
	return nil
}

func (s *SessionPageViewLocationData) String() string {
	if len(s.rawJSON) > 0 {
		if value, err := internal.StringifyJSON(s.rawJSON); err == nil {
			return value
		}
	}
	if value, err := internal.StringifyJSON(s); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", s)
}

type SessionPageViewViewPortData struct {
	// Viewport height in pixels
	Height *int `json:"height,omitempty" url:"height,omitempty"`
	// Viewport width in pixels
	Width *int `json:"width,omitempty" url:"width,omitempty"`

	extraProperties map[string]interface{}
	rawJSON         json.RawMessage
}

func (s *SessionPageViewViewPortData) GetHeight() *int {
	if s == nil {
		return nil
	}
	return s.Height
}

func (s *SessionPageViewViewPortData) GetWidth() *int {
	if s == nil {
		return nil
	}
	return s.Width
}

func (s *SessionPageViewViewPortData) GetExtraProperties() map[string]interface{} {
	return s.extraProperties
}

func (s *SessionPageViewViewPortData) UnmarshalJSON(data []byte) error {
	type unmarshaler SessionPageViewViewPortData
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*s = SessionPageViewViewPortData(value)
	extraProperties, err := internal.ExtractExtraProperties(data, *s)
	if err != nil {
		return err
	}
	s.extraProperties = extraProperties
	s.rawJSON = json.RawMessage(data)
	return nil
}

func (s *SessionPageViewViewPortData) String() string {
	if len(s.rawJSON) > 0 {
		if value, err := internal.StringifyJSON(s.rawJSON); err == nil {
			return value
		}
	}
	if value, err := internal.StringifyJSON(s); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", s)
}
