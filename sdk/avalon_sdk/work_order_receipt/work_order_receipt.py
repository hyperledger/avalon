# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import random

import avalon_crypto_utils.crypto_utility as crypto_utility
import avalon_crypto_utils.worker_signing as worker_signing
import avalon_crypto_utils.worker_hash as worker_hash

from error_code.error_status import ReceiptCreateStatus as ReceiptCreateStatus
from error_code.error_status import WorkOrderStatus
from enum import Enum, unique


@unique
class ReceiptCreateStatus(Enum):
    """
    Receipt creation status values:
    0 - PENDING. The work order is waiting to be processed by the worker
    1 - COMPLETED. The worker processed the Work Order and no more worker
        updates are expected
    2 - PROCESSED. The worker processed the Work Order, but additional worker
        updates are expected, e.g. oracle notifications
    3 - FAILED. The Work Order processing failed, e.g. by the worker service
        because of an invalid workerId
    4 - REJECTED. The Work Order is rejected by the smart contract,
        e.g. invalid workerServiceId
    5 to 254 - reserved
    255 - indicates any status
    >255 - application-specific values

    Defined in EEA spec 7.1.
    """
    PENDING = 0
    COMPLETED = 1
    PROCESSED = 2
    FAILED = 3
    REJECTED = 4


class WorkOrderReceiptRequest():
    """
    Class to create work order receipt APIs such as
    create, update, retrieve, and lookup.
    """

    def __init__(self):
        self.SIGNING_ALGORITHM = "SECP256K1"
        self.HASHING_ALGORITHM = "SHA-256"
        self.signer = worker_signing.WorkerSign()
        self.signer.generate_signing_key()
        self.hasher = worker_hash.WorkerHash()

    def create_receipt(self, wo_request,
                       receipt_create_status, signing_key, nonce=None):
        """
        Create a work order receipt corresponding to a workorder ID.

        Parameters:
        wo_request            JSON RPC work order request used to create the
                              work order request as defined in EEA spec 6.1.1
        receipt_create_status Receipt creation status
        signing_key           Private key of the signer
        nonce                 Optional random number or monotonic counter

        Returns:
        JSON RPC request of type dictionary
        """
        wo_request_params = wo_request["params"]
        wo_request_hash = \
            self.hasher.calculate_request_hash(wo_request_params)
        wo_request_hash_str = \
            crypto_utility.byte_array_to_base64(wo_request_hash)
        worker_id = wo_request_params["workerId"]
        requester_nonce = nonce
        if nonce is None:
            requester_nonce = str(random.randint(1, 10**10))
        public_key = self.signer.get_public_sign_key()
        wo_receipt_request = {
            "workOrderId": wo_request_params["workOrderId"],
            # TODO: workerServiceId is same as worker id,
            # needs to be updated with actual service id
            "workerServiceId": worker_id,
            "workerId": worker_id,
            "requesterId": wo_request_params["requesterId"],
            "receiptCreateStatus": receipt_create_status,
            "workOrderRequestHash": wo_request_hash_str,
            "requesterGeneratedNonce": requester_nonce,
            "signatureRules":
            self.HASHING_ALGORITHM + "/" + self.SIGNING_ALGORITHM,
            "receiptVerificationKey": public_key
        }
        wo_receipt_str = wo_receipt_request["workOrderId"] + \
            wo_receipt_request["workerServiceId"] + \
            wo_receipt_request["workerId"] + \
            wo_receipt_request["requesterId"] + \
            str(wo_receipt_request["receiptCreateStatus"]) + \
            wo_receipt_request["workOrderRequestHash"] + \
            wo_receipt_request["requesterGeneratedNonce"]
        wo_receipt_bytes = bytes(wo_receipt_str, "UTF-8")
        wo_receipt_hash = self.hasher.compute_message_hash(wo_receipt_bytes)
        wo_receipt_sign = self.signer.sign_message(wo_receipt_hash)
        wo_receipt_request["requesterSignature"] = wo_receipt_sign
        return wo_receipt_request

    def update_receipt(self, work_order_id, update_type,
                       update_data, signing_key):
        """
        Update the existing work order receipt with
        update_type and update_data.

        Parameters:
        work_order_id Work order ID whose receipt
                      needs to be updated
        update_type   Update type. These values correspond to
                      receipt status as defined in EEA Spec 7.1.1
        update_data   Update-specific data that depends on
                      the workOrderStatus
        Returns:
        JSON RPC work order update receipt request of type dictionary
        """
        data = json.dumps(update_data)
        if update_type in [ReceiptCreateStatus.PROCESSED.value,
                           ReceiptCreateStatus.COMPLETED.value]:
            # Work Order Receipt status is set to be completed or processed,
            # then update_data should be work order response.
            wo_resp_str = json.dumps(update_data)
            wo_resp_bytes = bytes(wo_resp_str, "UTF-8")
            # Hash of work order response is update_data
            wo_resp_hash = crypto_utility.compute_message_hash(wo_resp_bytes)
            wo_resp_hash_str = crypto_utility.byte_array_to_hex(wo_resp_hash)
            data = wo_resp_hash_str
        public_key = signing_key.verifying_key.to_pem().decode("ascii")
        updater_id = crypto_utility.strip_begin_end_public_key(public_key)

        wo_receipt_update = {
            "workOrderId": work_order_id,
            "updaterId": updater_id,
            "updateType": update_type,
            "updateData": data,
            "signatureRules":
            self.HASHING_ALGORITHM + "/" + self.SIGNING_ALGORITHM,
            "receiptVerificationKey": public_key
        }
        wo_receipt_str = wo_receipt_update["workOrderId"] + \
            str(wo_receipt_update["updateType"]) + \
            wo_receipt_update["updateData"]
        wo_receipt_bytes = bytes(wo_receipt_str, "UTF-8")
        wo_receipt_hash = crypto_utility.compute_message_hash(wo_receipt_bytes)
        wo_receipt_sign = self.signer.sign_message(wo_receipt_hash)
        wo_receipt_request["requesterSignature"] = wo_receipt_sign
        return wo_receipt_update
