package opcua

import (
	"strconv"

	"github.com/rom/otinv/internal/model"
)

// The message types, service identifiers and status codes of the OPC UA
// binary protocol (OPC UA Part 6).

// Message types. The three octets that open every message say which of them
// this is, and the fourth is the chunk marker.
const (
	msgHello        = "HEL"
	msgAcknowledge  = "ACK"
	msgError        = "ERR"
	msgReverseHello = "RHE"
	msgOpen         = "OPN"
	msgClose        = "CLO"
	msgMessage      = "MSG"
)

var messageTypes = map[string]string{
	msgHello:        "Hello",
	msgAcknowledge:  "Acknowledge",
	msgError:        "Error",
	msgReverseHello: "ReverseHello",
	msgOpen:         "OpenSecureChannel",
	msgClose:        "CloseSecureChannel",
	msgMessage:      "Message",
}

// Chunk markers (OPC UA Part 6, clause 6.7.2).
const (
	chunkFinal        = 'F'
	chunkIntermediate = 'C'
	chunkAbort        = 'A'
)

type serviceInfo struct {
	name  string
	class model.Classification
}

// services maps the binary encoding identifier of a service request or
// response to its name and classification.
//
// The identifiers are not guessable and getting one wrong would put the wrong
// operation on a device, so this table was generated from the OPC UA NodeIds
// table published with the standard (the Encoding_DefaultBinary object of
// each request and response) rather than written from memory. The capture in
// testdata corroborates nine of them.
//
// The classifications follow what each service does to the server. Read,
// Browse, Query and the subscription services read; Write and HistoryUpdate
// write; AddNodes, DeleteNodes and the reference services change the address
// space itself, which is the server's own structure, so they are program. Call
// is control: invoking a method is the one service that makes a device do
// something rather than read or write data, and it is what CLAUDE.md's rules
// on control commands are for. The channel and session services are the
// transport establishing itself, which is other.
var services = map[uint32]serviceInfo{
	397:   {"ServiceFault", model.ClassOther},
	422:   {"FindServersRequest", model.ClassDiscovery},
	425:   {"FindServersResponse", model.ClassDiscovery},
	428:   {"GetEndpointsRequest", model.ClassDiscovery},
	431:   {"GetEndpointsResponse", model.ClassDiscovery},
	437:   {"RegisterServerRequest", model.ClassDiscovery},
	440:   {"RegisterServerResponse", model.ClassDiscovery},
	446:   {"OpenSecureChannelRequest", model.ClassOther},
	449:   {"OpenSecureChannelResponse", model.ClassOther},
	452:   {"CloseSecureChannelRequest", model.ClassOther},
	455:   {"CloseSecureChannelResponse", model.ClassOther},
	461:   {"CreateSessionRequest", model.ClassOther},
	464:   {"CreateSessionResponse", model.ClassOther},
	467:   {"ActivateSessionRequest", model.ClassOther},
	470:   {"ActivateSessionResponse", model.ClassOther},
	473:   {"CloseSessionRequest", model.ClassOther},
	476:   {"CloseSessionResponse", model.ClassOther},
	479:   {"CancelRequest", model.ClassOther},
	482:   {"CancelResponse", model.ClassOther},
	488:   {"AddNodesRequest", model.ClassProgram},
	491:   {"AddNodesResponse", model.ClassProgram},
	494:   {"AddReferencesRequest", model.ClassProgram},
	497:   {"AddReferencesResponse", model.ClassProgram},
	500:   {"DeleteNodesRequest", model.ClassProgram},
	503:   {"DeleteNodesResponse", model.ClassProgram},
	506:   {"DeleteReferencesRequest", model.ClassProgram},
	509:   {"DeleteReferencesResponse", model.ClassProgram},
	527:   {"BrowseRequest", model.ClassRead},
	530:   {"BrowseResponse", model.ClassRead},
	533:   {"BrowseNextRequest", model.ClassRead},
	536:   {"BrowseNextResponse", model.ClassRead},
	554:   {"TranslateBrowsePathsToNodeIdsRequest", model.ClassRead},
	557:   {"TranslateBrowsePathsToNodeIdsResponse", model.ClassRead},
	560:   {"RegisterNodesRequest", model.ClassOther},
	563:   {"RegisterNodesResponse", model.ClassOther},
	566:   {"UnregisterNodesRequest", model.ClassOther},
	569:   {"UnregisterNodesResponse", model.ClassOther},
	615:   {"QueryFirstRequest", model.ClassRead},
	618:   {"QueryFirstResponse", model.ClassRead},
	621:   {"QueryNextRequest", model.ClassRead},
	624:   {"QueryNextResponse", model.ClassRead},
	631:   {"ReadRequest", model.ClassRead},
	634:   {"ReadResponse", model.ClassRead},
	664:   {"HistoryReadRequest", model.ClassRead},
	667:   {"HistoryReadResponse", model.ClassRead},
	673:   {"WriteRequest", model.ClassWrite},
	676:   {"WriteResponse", model.ClassWrite},
	700:   {"HistoryUpdateRequest", model.ClassWrite},
	703:   {"HistoryUpdateResponse", model.ClassWrite},
	712:   {"CallRequest", model.ClassControl},
	715:   {"CallResponse", model.ClassControl},
	751:   {"CreateMonitoredItemsRequest", model.ClassRead},
	754:   {"CreateMonitoredItemsResponse", model.ClassRead},
	763:   {"ModifyMonitoredItemsRequest", model.ClassRead},
	766:   {"ModifyMonitoredItemsResponse", model.ClassRead},
	769:   {"SetMonitoringModeRequest", model.ClassOther},
	772:   {"SetMonitoringModeResponse", model.ClassOther},
	775:   {"SetTriggeringRequest", model.ClassOther},
	778:   {"SetTriggeringResponse", model.ClassOther},
	781:   {"DeleteMonitoredItemsRequest", model.ClassOther},
	784:   {"DeleteMonitoredItemsResponse", model.ClassOther},
	787:   {"CreateSubscriptionRequest", model.ClassOther},
	790:   {"CreateSubscriptionResponse", model.ClassOther},
	793:   {"ModifySubscriptionRequest", model.ClassOther},
	796:   {"ModifySubscriptionResponse", model.ClassOther},
	799:   {"SetPublishingModeRequest", model.ClassOther},
	802:   {"SetPublishingModeResponse", model.ClassOther},
	826:   {"PublishRequest", model.ClassRead},
	829:   {"PublishResponse", model.ClassRead},
	832:   {"RepublishRequest", model.ClassRead},
	835:   {"RepublishResponse", model.ClassRead},
	841:   {"TransferSubscriptionsRequest", model.ClassOther},
	844:   {"TransferSubscriptionsResponse", model.ClassOther},
	847:   {"DeleteSubscriptionsRequest", model.ClassOther},
	850:   {"DeleteSubscriptionsResponse", model.ClassOther},
	12208: {"FindServersOnNetworkRequest", model.ClassDiscovery},
	12209: {"FindServersOnNetworkResponse", model.ClassDiscovery},
	12211: {"RegisterServer2Request", model.ClassDiscovery},
	12212: {"RegisterServer2Response", model.ClassDiscovery},
}

func service(id uint32) (serviceInfo, bool) {
	if info, ok := services[id]; ok {
		return info, true
	}
	return serviceInfo{"Service_" + strconv.FormatUint(uint64(id), 10), model.ClassOther}, false
}

// statusCodes name the result a service or a transport error carries. The
// table is generated from the status codes published with the standard; a
// code outside it is reported as its number.
//
// Four of these are the ones worth watching on an OPC UA server:
// BadUserAccessDenied and BadIdentityTokenRejected are a client being refused,
// BadSecurityChecksFailed is a client whose certificate or signature did not
// hold up, and BadTooManySessions is what exhaustion looks like.
var statusCodes = map[uint32]string{
	0x00000000: "Good",
	0x40000000: "Uncertain",
	0x80000000: "Bad",
	0x80010000: "BadUnexpectedError",
	0x80020000: "BadInternalError",
	0x80030000: "BadOutOfMemory",
	0x80040000: "BadResourceUnavailable",
	0x80050000: "BadCommunicationError",
	0x80060000: "BadEncodingError",
	0x80070000: "BadDecodingError",
	0x80080000: "BadEncodingLimitsExceeded",
	0x80B80000: "BadRequestTooLarge",
	0x80B90000: "BadResponseTooLarge",
	0x80090000: "BadUnknownResponse",
	0x800A0000: "BadTimeout",
	0x800B0000: "BadServiceUnsupported",
	0x800C0000: "BadShutdown",
	0x800D0000: "BadServerNotConnected",
	0x800E0000: "BadServerHalted",
	0x800F0000: "BadNothingToDo",
	0x80100000: "BadTooManyOperations",
	0x80DB0000: "BadTooManyMonitoredItems",
	0x80110000: "BadDataTypeIdUnknown",
	0x80120000: "BadCertificateInvalid",
	0x80130000: "BadSecurityChecksFailed",
	0x81140000: "BadCertificatePolicyCheckFailed",
	0x80140000: "BadCertificateTimeInvalid",
	0x80150000: "BadCertificateIssuerTimeInvalid",
	0x80160000: "BadCertificateHostNameInvalid",
	0x80170000: "BadCertificateUriInvalid",
	0x80180000: "BadCertificateUseNotAllowed",
	0x80190000: "BadCertificateIssuerUseNotAllowed",
	0x801A0000: "BadCertificateUntrusted",
	0x801B0000: "BadCertificateRevocationUnknown",
	0x801C0000: "BadCertificateIssuerRevocationUnknown",
	0x801D0000: "BadCertificateRevoked",
	0x801E0000: "BadCertificateIssuerRevoked",
	0x810D0000: "BadCertificateChainIncomplete",
	0x801F0000: "BadUserAccessDenied",
	0x80200000: "BadIdentityTokenInvalid",
	0x80210000: "BadIdentityTokenRejected",
	0x80220000: "BadSecureChannelIdInvalid",
	0x80230000: "BadInvalidTimestamp",
	0x80240000: "BadNonceInvalid",
	0x80250000: "BadSessionIdInvalid",
	0x80260000: "BadSessionClosed",
	0x80270000: "BadSessionNotActivated",
	0x80280000: "BadSubscriptionIdInvalid",
	0x802A0000: "BadRequestHeaderInvalid",
	0x802B0000: "BadTimestampsToReturnInvalid",
	0x802C0000: "BadRequestCancelledByClient",
	0x80E50000: "BadTooManyArguments",
	0x810E0000: "BadLicenseExpired",
	0x810F0000: "BadLicenseLimitsExceeded",
	0x81100000: "BadLicenseNotAvailable",
	0x002D0000: "GoodSubscriptionTransferred",
	0x002E0000: "GoodCompletesAsynchronously",
	0x002F0000: "GoodOverload",
	0x00300000: "GoodClamped",
	0x80310000: "BadNoCommunication",
	0x80320000: "BadWaitingForInitialData",
	0x80330000: "BadNodeIdInvalid",
	0x80340000: "BadNodeIdUnknown",
	0x80350000: "BadAttributeIdInvalid",
	0x80360000: "BadIndexRangeInvalid",
	0x80370000: "BadIndexRangeNoData",
	0x80380000: "BadDataEncodingInvalid",
	0x80390000: "BadDataEncodingUnsupported",
	0x803A0000: "BadNotReadable",
	0x803B0000: "BadNotWritable",
	0x803C0000: "BadOutOfRange",
	0x803D0000: "BadNotSupported",
	0x803E0000: "BadNotFound",
	0x803F0000: "BadObjectDeleted",
	0x80400000: "BadNotImplemented",
	0x80410000: "BadMonitoringModeInvalid",
	0x80420000: "BadMonitoredItemIdInvalid",
	0x80430000: "BadMonitoredItemFilterInvalid",
	0x80440000: "BadMonitoredItemFilterUnsupported",
	0x80450000: "BadFilterNotAllowed",
	0x80460000: "BadStructureMissing",
	0x80470000: "BadEventFilterInvalid",
	0x80480000: "BadContentFilterInvalid",
	0x80C10000: "BadFilterOperatorInvalid",
	0x80C20000: "BadFilterOperatorUnsupported",
	0x80C30000: "BadFilterOperandCountMismatch",
	0x80490000: "BadFilterOperandInvalid",
	0x80C40000: "BadFilterElementInvalid",
	0x80C50000: "BadFilterLiteralInvalid",
	0x804A0000: "BadContinuationPointInvalid",
	0x804B0000: "BadNoContinuationPoints",
	0x804C0000: "BadReferenceTypeIdInvalid",
	0x804D0000: "BadBrowseDirectionInvalid",
	0x804E0000: "BadNodeNotInView",
	0x81120000: "BadNumericOverflow",
	0x804F0000: "BadServerUriInvalid",
	0x80500000: "BadServerNameMissing",
	0x80510000: "BadDiscoveryUrlMissing",
	0x80520000: "BadSemaphoreFileMissing",
	0x80530000: "BadRequestTypeInvalid",
	0x80540000: "BadSecurityModeRejected",
	0x80550000: "BadSecurityPolicyRejected",
	0x80560000: "BadTooManySessions",
	0x80570000: "BadUserSignatureInvalid",
	0x80580000: "BadApplicationSignatureInvalid",
	0x80590000: "BadNoValidCertificates",
	0x80C60000: "BadIdentityChangeNotSupported",
	0x805A0000: "BadRequestCancelledByRequest",
	0x805B0000: "BadParentNodeIdInvalid",
	0x805C0000: "BadReferenceNotAllowed",
	0x805D0000: "BadNodeIdRejected",
	0x805E0000: "BadNodeIdExists",
	0x805F0000: "BadNodeClassInvalid",
	0x80600000: "BadBrowseNameInvalid",
	0x80610000: "BadBrowseNameDuplicated",
	0x80620000: "BadNodeAttributesInvalid",
	0x80630000: "BadTypeDefinitionInvalid",
	0x80640000: "BadSourceNodeIdInvalid",
	0x80650000: "BadTargetNodeIdInvalid",
	0x80660000: "BadDuplicateReferenceNotAllowed",
	0x80670000: "BadInvalidSelfReference",
	0x80680000: "BadReferenceLocalOnly",
	0x80690000: "BadNoDeleteRights",
	0x40BC0000: "UncertainReferenceNotDeleted",
	0x806A0000: "BadServerIndexInvalid",
	0x806B0000: "BadViewIdUnknown",
	0x80C90000: "BadViewTimestampInvalid",
	0x80CA0000: "BadViewParameterMismatch",
	0x80CB0000: "BadViewVersionInvalid",
	0x40C00000: "UncertainNotAllNodesAvailable",
	0x00BA0000: "GoodResultsMayBeIncomplete",
	0x80C80000: "BadNotTypeDefinition",
	0x406C0000: "UncertainReferenceOutOfServer",
	0x806D0000: "BadTooManyMatches",
	0x806E0000: "BadQueryTooComplex",
	0x806F0000: "BadNoMatch",
	0x80700000: "BadMaxAgeInvalid",
	0x80E60000: "BadSecurityModeInsufficient",
	0x80710000: "BadHistoryOperationInvalid",
	0x80720000: "BadHistoryOperationUnsupported",
	0x80BD0000: "BadInvalidTimestampArgument",
	0x80730000: "BadWriteNotSupported",
	0x80740000: "BadTypeMismatch",
	0x80750000: "BadMethodInvalid",
	0x80760000: "BadArgumentsMissing",
	0x81110000: "BadNotExecutable",
	0x80770000: "BadTooManySubscriptions",
	0x80780000: "BadTooManyPublishRequests",
	0x80790000: "BadNoSubscription",
	0x807A0000: "BadSequenceNumberUnknown",
	0x00DF0000: "GoodRetransmissionQueueNotSupported",
	0x807B0000: "BadMessageNotAvailable",
	0x807C0000: "BadInsufficientClientProfile",
	0x80BF0000: "BadStateNotActive",
	0x81150000: "BadAlreadyExists",
	0x807D0000: "BadTcpServerTooBusy",
	0x807E0000: "BadTcpMessageTypeInvalid",
	0x807F0000: "BadTcpSecureChannelUnknown",
	0x80800000: "BadTcpMessageTooLarge",
	0x80810000: "BadTcpNotEnoughResources",
	0x80820000: "BadTcpInternalError",
	0x80830000: "BadTcpEndpointUrlInvalid",
	0x80840000: "BadRequestInterrupted",
	0x80850000: "BadRequestTimeout",
	0x80860000: "BadSecureChannelClosed",
	0x80870000: "BadSecureChannelTokenUnknown",
	0x80880000: "BadSequenceNumberInvalid",
	0x80BE0000: "BadProtocolVersionUnsupported",
	0x80890000: "BadConfigurationError",
	0x808A0000: "BadNotConnected",
	0x808B0000: "BadDeviceFailure",
	0x808C0000: "BadSensorFailure",
	0x808D0000: "BadOutOfService",
	0x808E0000: "BadDeadbandFilterInvalid",
	0x408F0000: "UncertainNoCommunicationLastUsableValue",
	0x40900000: "UncertainLastUsableValue",
	0x40910000: "UncertainSubstituteValue",
	0x40920000: "UncertainInitialValue",
	0x40930000: "UncertainSensorNotAccurate",
	0x40940000: "UncertainEngineeringUnitsExceeded",
	0x40950000: "UncertainSubNormal",
	0x00960000: "GoodLocalOverride",
	0x80970000: "BadRefreshInProgress",
	0x80980000: "BadConditionAlreadyDisabled",
	0x80CC0000: "BadConditionAlreadyEnabled",
	0x80990000: "BadConditionDisabled",
	0x809A0000: "BadEventIdUnknown",
	0x80BB0000: "BadEventNotAcknowledgeable",
	0x80CD0000: "BadDialogNotActive",
	0x80CE0000: "BadDialogResponseInvalid",
	0x80CF0000: "BadConditionBranchAlreadyAcked",
	0x80D00000: "BadConditionBranchAlreadyConfirmed",
	0x80D10000: "BadConditionAlreadyShelved",
	0x80D20000: "BadConditionNotShelved",
	0x80D30000: "BadShelvingTimeOutOfRange",
	0x809B0000: "BadNoData",
	0x80D70000: "BadBoundNotFound",
	0x80D80000: "BadBoundNotSupported",
	0x809D0000: "BadDataLost",
	0x809E0000: "BadDataUnavailable",
	0x809F0000: "BadEntryExists",
	0x80A00000: "BadNoEntryExists",
	0x80A10000: "BadTimestampNotSupported",
	0x00A20000: "GoodEntryInserted",
	0x00A30000: "GoodEntryReplaced",
	0x40A40000: "UncertainDataSubNormal",
	0x00A50000: "GoodNoData",
	0x00A60000: "GoodMoreData",
	0x80D40000: "BadAggregateListMismatch",
	0x80D50000: "BadAggregateNotSupported",
	0x80D60000: "BadAggregateInvalidInputs",
	0x80DA0000: "BadAggregateConfigurationRejected",
	0x00D90000: "GoodDataIgnored",
	0x80E40000: "BadRequestNotAllowed",
	0x81130000: "BadRequestNotComplete",
	0x80E80000: "BadTransactionPending",
	0x811F0000: "BadTicketRequired",
	0x81200000: "BadTicketInvalid",
	0x00DC0000: "GoodEdited",
	0x00DD0000: "GoodPostActionFailed",
	0x40DE0000: "UncertainDominantValueChanged",
	0x00E00000: "GoodDependentValueChanged",
	0x80E10000: "BadDominantValueChanged",
	0x40E20000: "UncertainDependentValueChanged",
	0x80E30000: "BadDependentValueChanged",
	0x01160000: "GoodEdited_DependentValueChanged",
	0x01170000: "GoodEdited_DominantValueChanged",
	0x01180000: "GoodEdited_DominantValueChanged_DependentValueChanged",
	0x81190000: "BadEdited_OutOfRange",
	0x811A0000: "BadInitialValue_OutOfRange",
	0x811B0000: "BadOutOfRange_DominantValueChanged",
	0x811C0000: "BadEdited_OutOfRange_DominantValueChanged",
	0x811D0000: "BadOutOfRange_DominantValueChanged_DependentValueChanged",
	0x811E0000: "BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged",
	0x00A70000: "GoodCommunicationEvent",
	0x00A80000: "GoodShutdownEvent",
	0x00A90000: "GoodCallAgain",
	0x00AA0000: "GoodNonCriticalTimeout",
	0x80AB0000: "BadInvalidArgument",
	0x80AC0000: "BadConnectionRejected",
	0x80AD0000: "BadDisconnect",
	0x80AE0000: "BadConnectionClosed",
	0x80AF0000: "BadInvalidState",
	0x80B00000: "BadEndOfStream",
	0x80B10000: "BadNoDataAvailable",
	0x80B20000: "BadWaitingForResponse",
	0x80B30000: "BadOperationAbandoned",
	0x80B40000: "BadExpectedStreamToBlock",
	0x80B50000: "BadWouldBlock",
	0x80B60000: "BadSyntaxError",
	0x80B70000: "BadMaxConnectionsReached",
}

// statusName renders a status code. The top sixteen bits carry the code and
// the rest are flags, so a code is looked up on its high half.
func statusName(code uint32) string {
	if name, ok := statusCodes[code&0xFFFF0000]; ok {
		return name
	}
	return "Status_0x" + hex32(code)
}

// severity reports whether a status code says the operation failed. The top
// two bits are the severity (OPC UA Part 4, clause 7.34).
func isBad(code uint32) bool { return code&0xC0000000 == 0x80000000 }

// messageSecurityModes are what an endpoint offers (OPC UA Part 4, clause
// 7.15). None means nothing is signed or encrypted: the traffic can be read
// and forged by anyone on the segment, which is what CLAUDE.md's rule on
// SecurityMode None is about.
var messageSecurityModes = map[uint32]string{
	0: "Invalid",
	1: "None",
	2: "Sign",
	3: "SignAndEncrypt",
}

func securityModeName(mode uint32) string {
	if name, ok := messageSecurityModes[mode]; ok {
		return name
	}
	return "Mode_" + strconv.FormatUint(uint64(mode), 10)
}

// userTokenTypes say how a client proves who it is, which separates a server
// that lets anyone in from one that asks for a password or a certificate
// (OPC UA Part 4, clause 7.36).
var userTokenTypes = map[uint32]string{
	0: "Anonymous",
	1: "UserName",
	2: "Certificate",
	3: "IssuedToken",
}

func userTokenName(kind uint32) string {
	if name, ok := userTokenTypes[kind]; ok {
		return name
	}
	return "TokenType_" + strconv.FormatUint(uint64(kind), 10)
}

// applicationTypes say what part an application plays: a server, a client, or
// the discovery server that lists them (OPC UA Part 4, clause 7.1).
var applicationTypes = map[uint32]string{
	0: "Server",
	1: "Client",
	2: "ClientAndServer",
	3: "DiscoveryServer",
}

func applicationTypeName(kind uint32) string {
	if name, ok := applicationTypes[kind]; ok {
		return name
	}
	return "ApplicationType_" + strconv.FormatUint(uint64(kind), 10)
}

// securityPolicy shortens a security policy URI to the part that matters. The
// URIs are long and all share a prefix; what an analyst reads is the fragment
// after it.
func securityPolicy(uri string) string {
	const prefix = "http://opcfoundation.org/UA/SecurityPolicy#"
	if len(uri) > len(prefix) && uri[:len(prefix)] == prefix {
		return uri[len(prefix):]
	}
	return uri
}

// Attribute identifiers of a node (OPC UA Part 6, annex A.1). A read or a
// write names one, and which one says whether a client is reading a value or
// the structure around it.
var attributes = map[uint32]string{
	1:  "NodeId",
	2:  "NodeClass",
	3:  "BrowseName",
	4:  "DisplayName",
	5:  "Description",
	6:  "WriteMask",
	7:  "UserWriteMask",
	13: "Value",
	14: "DataType",
	15: "ValueRank",
	16: "ArrayDimensions",
	17: "AccessLevel",
	18: "UserAccessLevel",
	20: "Historizing",
	21: "Executable",
	22: "UserExecutable",
}

func attributeName(id uint32) string {
	if name, ok := attributes[id]; ok {
		return name
	}
	return "Attribute_" + strconv.FormatUint(uint64(id), 10)
}

const hexDigits = "0123456789abcdef"

func hex32(v uint32) string {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = hexDigits[v&0xf]
		v >>= 4
	}
	return string(out)
}
