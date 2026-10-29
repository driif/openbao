// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	kmiplib "github.com/ovh/kmip-go"
)

// SupportedOperations is what Query advertises. The listener's router
// answers DiscoverVersions itself; every other operation has a route.
var SupportedOperations = []kmiplib.Operation{
	kmiplib.OperationRegister,
	kmiplib.OperationCreate,
	kmiplib.OperationGet,
	kmiplib.OperationGetAttributes,
	kmiplib.OperationGetAttributeList,
	kmiplib.OperationAddAttribute,
	kmiplib.OperationReKey,
	kmiplib.OperationLocate,
	kmiplib.OperationActivate,
	kmiplib.OperationRevoke,
	kmiplib.OperationDestroy,
	kmiplib.OperationEncrypt,
	kmiplib.OperationDecrypt,
	kmiplib.OperationSign,
	kmiplib.OperationSignatureVerify,
	kmiplib.OperationQuery,
	kmiplib.OperationDiscoverVersions,
}

var SupportedObjectTypes = []kmiplib.ObjectType{
	kmiplib.ObjectTypeSymmetricKey,
	kmiplib.ObjectTypePrivateKey,
	kmiplib.ObjectTypePublicKey,
}
