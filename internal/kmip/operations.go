// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	kmiplib "github.com/ovh/kmip-go"
)

var SupportedOperations = []kmiplib.Operation{
	kmiplib.OperationRegister,
	kmiplib.OperationCreate,
	kmiplib.OperationGet,
	kmiplib.OperationGetAttributes,
	kmiplib.OperationLocate,
	kmiplib.OperationActivate,
	kmiplib.OperationRevoke,
	kmiplib.OperationDestroy,
	kmiplib.OperationEncrypt,
	kmiplib.OperationDecrypt,
	kmiplib.OperationSign,
	kmiplib.OperationSignatureVerify,
	kmiplib.OperationQuery,
}

var SupportedObjectTypes = []kmiplib.ObjectType{
	kmiplib.ObjectTypeSymmetricKey,
	kmiplib.ObjectTypePrivateKey,
	kmiplib.ObjectTypePublicKey,
}
