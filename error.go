package ldapcpp

import (
	"fmt"
	"strconv"
	"strings"
)

// LDAP Result Codes
const (
	LDAPResultSuccess                            = 0
	LDAPResultOperationsError                    = 1
	LDAPResultProtocolError                      = 2
	LDAPResultTimeLimitExceeded                  = 3
	LDAPResultSizeLimitExceeded                  = 4
	LDAPResultCompareFalse                       = 5
	LDAPResultCompareTrue                        = 6
	LDAPResultAuthMethodNotSupported             = 7
	LDAPResultStrongAuthRequired                 = 8
	LDAPResultReferral                           = 10
	LDAPResultAdminLimitExceeded                 = 11
	LDAPResultUnavailableCriticalExtension       = 12
	LDAPResultConfidentialityRequired            = 13
	LDAPResultSaslBindInProgress                 = 14
	LDAPResultNoSuchAttribute                    = 16
	LDAPResultUndefinedAttributeType             = 17
	LDAPResultInappropriateMatching              = 18
	LDAPResultConstraintViolation                = 19
	LDAPResultAttributeOrValueExists             = 20
	LDAPResultInvalidAttributeSyntax             = 21
	LDAPResultNoSuchObject                       = 32
	LDAPResultAliasProblem                       = 33
	LDAPResultInvalidDNSyntax                    = 34
	LDAPResultIsLeaf                             = 35
	LDAPResultAliasDereferencingProblem          = 36
	LDAPResultInappropriateAuthentication        = 48
	LDAPResultInvalidCredentials                 = 49
	LDAPResultInsufficientAccessRights           = 50
	LDAPResultBusy                               = 51
	LDAPResultUnavailable                        = 52
	LDAPResultUnwillingToPerform                 = 53
	LDAPResultLoopDetect                         = 54
	LDAPResultSortControlMissing                 = 60
	LDAPResultOffsetRangeError                   = 61
	LDAPResultNamingViolation                    = 64
	LDAPResultObjectClassViolation               = 65
	LDAPResultNotAllowedOnNonLeaf                = 66
	LDAPResultNotAllowedOnRDN                    = 67
	LDAPResultEntryAlreadyExists                 = 68
	LDAPResultObjectClassModsProhibited          = 69
	LDAPResultResultsTooLarge                    = 70
	LDAPResultAffectsMultipleDSAs                = 71
	LDAPResultVirtualListViewErrorOrControlError = 76
	LDAPResultOther                              = 80
	LDAPResultServerDown                         = 81
	LDAPResultLocalError                         = 82
	LDAPResultEncodingError                      = 83
	LDAPResultDecodingError                      = 84
	LDAPResultTimeout                            = 85
	LDAPResultAuthUnknown                        = 86
	LDAPResultFilterError                        = 87
	LDAPResultUserCanceled                       = 88
	LDAPResultParamError                         = 89
	LDAPResultNoMemory                           = 90
	LDAPResultConnectError                       = 91
	LDAPResultNotSupported                       = 92
	LDAPResultControlNotFound                    = 93
	LDAPResultNoResultsReturned                  = 94
	LDAPResultMoreResultsToReturn                = 95
	LDAPResultClientLoop                         = 96
	LDAPResultReferralLimitExceeded              = 97
	LDAPResultInvalidResponse                    = 100
	LDAPResultAmbiguousResponse                  = 101
	LDAPResultTLSNotSupported                    = 112
	LDAPResultIntermediateResponse               = 113
	LDAPResultUnknownType                        = 114
	LDAPResultCanceled                           = 118
	LDAPResultNoSuchOperation                    = 119
	LDAPResultTooLate                            = 120
	LDAPResultCannotCancel                       = 121
	LDAPResultAssertionFailed                    = 122
	LDAPResultAuthorizationDenied                = 123
	LDAPResultSyncRefreshRequired                = 4096

	ErrorNetwork            = 200
	ErrorFilterCompile      = 201
	ErrorFilterDecompile    = 202
	ErrorDebugging          = 203
	ErrorUnexpectedMessage  = 204
	ErrorUnexpectedResponse = 205
	ErrorEmptyPassword      = 206
)

// LDAPResultCodeMap contains string descriptions for LDAP error codes
var LDAPResultCodeMap = map[uint16]string{
	LDAPResultSuccess:                            "Success",
	LDAPResultOperationsError:                    "Operations Error",
	LDAPResultProtocolError:                      "Protocol Error",
	LDAPResultTimeLimitExceeded:                  "Time Limit Exceeded",
	LDAPResultSizeLimitExceeded:                  "Size Limit Exceeded",
	LDAPResultCompareFalse:                       "Compare False",
	LDAPResultCompareTrue:                        "Compare True",
	LDAPResultAuthMethodNotSupported:             "Auth Method Not Supported",
	LDAPResultStrongAuthRequired:                 "Strong Auth Required",
	LDAPResultReferral:                           "Referral",
	LDAPResultAdminLimitExceeded:                 "Admin Limit Exceeded",
	LDAPResultUnavailableCriticalExtension:       "Unavailable Critical Extension",
	LDAPResultConfidentialityRequired:            "Confidentiality Required",
	LDAPResultSaslBindInProgress:                 "Sasl Bind In Progress",
	LDAPResultNoSuchAttribute:                    "No Such Attribute",
	LDAPResultUndefinedAttributeType:             "Undefined Attribute Type",
	LDAPResultInappropriateMatching:              "Inappropriate Matching",
	LDAPResultConstraintViolation:                "Constraint Violation",
	LDAPResultAttributeOrValueExists:             "Attribute Or Value Exists",
	LDAPResultInvalidAttributeSyntax:             "Invalid Attribute Syntax",
	LDAPResultNoSuchObject:                       "No Such Object",
	LDAPResultAliasProblem:                       "Alias Problem",
	LDAPResultInvalidDNSyntax:                    "Invalid DN Syntax",
	LDAPResultIsLeaf:                             "Is Leaf",
	LDAPResultAliasDereferencingProblem:          "Alias Dereferencing Problem",
	LDAPResultInappropriateAuthentication:        "Inappropriate Authentication",
	LDAPResultInvalidCredentials:                 "Invalid Credentials",
	LDAPResultInsufficientAccessRights:           "Insufficient Access Rights",
	LDAPResultBusy:                               "Busy",
	LDAPResultUnavailable:                        "Unavailable",
	LDAPResultUnwillingToPerform:                 "Unwilling To Perform",
	LDAPResultLoopDetect:                         "Loop Detect",
	LDAPResultSortControlMissing:                 "Sort Control Missing",
	LDAPResultOffsetRangeError:                   "Result Offset Range Error",
	LDAPResultNamingViolation:                    "Naming Violation",
	LDAPResultObjectClassViolation:               "Object Class Violation",
	LDAPResultResultsTooLarge:                    "Results Too Large",
	LDAPResultNotAllowedOnNonLeaf:                "Not Allowed On Non Leaf",
	LDAPResultNotAllowedOnRDN:                    "Not Allowed On RDN",
	LDAPResultEntryAlreadyExists:                 "Entry Already Exists",
	LDAPResultObjectClassModsProhibited:          "Object Class Mods Prohibited",
	LDAPResultAffectsMultipleDSAs:                "Affects Multiple DSAs",
	LDAPResultVirtualListViewErrorOrControlError: "Failed because of a problem related to the virtual list view",
	LDAPResultOther:                              "Other",
	LDAPResultServerDown:                         "Cannot establish a connection",
	LDAPResultLocalError:                         "An error occurred",
	LDAPResultEncodingError:                      "LDAP encountered an error while encoding",
	LDAPResultDecodingError:                      "LDAP encountered an error while decoding",
	LDAPResultTimeout:                            "LDAP timeout while waiting for a response from the server",
	LDAPResultAuthUnknown:                        "The auth method requested in a bind request is unknown",
	LDAPResultFilterError:                        "An error occurred while encoding the given search filter",
	LDAPResultUserCanceled:                       "The user canceled the operation",
	LDAPResultParamError:                         "An invalid parameter was specified",
	LDAPResultNoMemory:                           "Out of memory error",
	LDAPResultConnectError:                       "A connection to the server could not be established",
	LDAPResultNotSupported:                       "An attempt has been made to use a feature not supported LDAP",
	LDAPResultControlNotFound:                    "The controls required to perform the requested operation were not found",
	LDAPResultNoResultsReturned:                  "No results were returned from the server",
	LDAPResultMoreResultsToReturn:                "There are more results in the chain of results",
	LDAPResultClientLoop:                         "A loop has been detected. For example when following referrals",
	LDAPResultReferralLimitExceeded:              "The referral hop limit has been exceeded",
	LDAPResultCanceled:                           "Operation was canceled",
	LDAPResultNoSuchOperation:                    "Server has no knowledge of the operation requested for cancellation",
	LDAPResultTooLate:                            "Too late to cancel the outstanding operation",
	LDAPResultCannotCancel:                       "The identified operation does not support cancellation or the cancel operation cannot be performed",
	LDAPResultAssertionFailed:                    "An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed",
	LDAPResultSyncRefreshRequired:                "Refresh Required",
	LDAPResultInvalidResponse:                    "Invalid Response",
	LDAPResultAmbiguousResponse:                  "Ambiguous Response",
	LDAPResultTLSNotSupported:                    "Tls Not Supported",
	LDAPResultIntermediateResponse:               "Intermediate Response",
	LDAPResultUnknownType:                        "Unknown Type",
	LDAPResultAuthorizationDenied:                "Authorization Denied",

	ErrorNetwork:            "Network Error",
	ErrorFilterCompile:      "Filter Compile Error",
	ErrorFilterDecompile:    "Filter Decompile Error",
	ErrorDebugging:          "Debugging Error",
	ErrorUnexpectedMessage:  "Unexpected Message",
	ErrorUnexpectedResponse: "Unexpected Response",
	ErrorEmptyPassword:      "Empty password not allowed by the client",
}

// Error holds LDAP error information
type Error struct {
	// Msg is the error message
	Msg string

	// ResultCode is the LDAP error code
	ResultCode uint16
}

func (err Error) Error() string {
	return fmt.Sprintf("LDAP Result Code %d %q: %s", err.ResultCode, LDAPResultCodeMap[err.ResultCode], err.Msg)
}

// Recover is a method that tries to recover from panics, and if it succeeds
func Recover(err *error) {
	if rec := recover(); rec != nil {
		msg := rec.(string)
		var resultCode uint16

		if err_splitted := strings.SplitN(msg, ":", 2); len(err_splitted) > 1 {
			msg = err_splitted[1]

			if code, code_err := strconv.Atoi(err_splitted[0]); code_err == nil {
				resultCode = uint16(code)
			}
		}

		*err = Error{
			Msg:        msg,
			ResultCode: resultCode,
		}

	}
}

// NewError creates an LDAP error with the given code and underlying error
func NewError(resultCode uint16, err error) error {
	return &Error{ResultCode: resultCode, Msg: err.Error()}
}
