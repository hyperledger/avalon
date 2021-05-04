#! /usr/bin/env python3

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

import os
import sys
import json
import argparse
import logging
import config.config as pconfig
from direct_model_generic_client import DirectModelGenericClient
from proxy_model_generic_client import ProxyModelGenericClient
import utility.hex_utils as hex_utils
import avalon_crypto_utils.worker_encryption as worker_encrypt
import avalon_crypto_utils.worker_signing as worker_signing

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
TCF_HOME = os.environ.get("TCF_HOME", "../../../")


class GenericClient():
    """
    Generic client class to test end to end flow
    for both direct model and proxy model
    """

    def __init__(self, args):
        # Parse command line arguments
        options = self._parse_command_line(args)
        # Read config params
        if options.config:
            self._config = self._parse_config_file(options.config)
        else:
            self._config = self._parse_config_file(
                TCF_HOME +
                "/sdk/avalon_sdk/tcf_connector.toml")
        if self._config is None:
            logging.error("\n Error in parsing config file: {}\n")
            sys.exit(-1)
        if options.blockchain:
            self._config['blockchain']['type'] = options.blockchain
            self._blockchain = options.blockchain
        else:
            self._blockchain = self._config['blockchain']['type']

        self._is_direct_mode = False
        # Mode
        self._mode = options.mode

        # Attestation type
        self._attestation = options.attestation

        # Http JSON RPC listener uri
        self._uri = options.uri
        if self._uri:
            self._config["tcf"]["json_rpc_uri"] = self._uri

        # Address of smart contract
        self._address = options.address
        if self._address:
            if self._mode == "listing":
                self._config["ethereum"]["direct_registry_contract_address"] =\
                    self._address
            elif self._mode == "registry":
                logging.error(
                    "\n Only Worker registry listing address is supported." +
                    "Worker registry address is unsupported \n")
                sys.exit(-1)

        bc_type = self._blockchain
        if self._uri or self._address:
            self._is_direct_mode = True
        elif bc_type == 'fabric' or bc_type == 'ethereum':
            self._is_direct_mode = False

        # worker id
        self._worker_id = options.worker_id
        self._worker_id_hex = options.worker_id_hex

        self._worker_id = self._worker_id_hex if not self._worker_id \
            else hex_utils.get_worker_id_from_name(self._worker_id)

        # work load id of worker
        self._workload_id = options.workload_id
        if not self._workload_id:
            logging.error("\nWorkload id is mandatory\n")
            sys.exit(-1)
        # work order input data
        self._in_data = options.in_data

        # Option to send input data in plain text
        self._in_data_plain_text = options.in_data_plain

        # show receipt in output
        self._show_receipt = options.receipt

        # show decrypted result in output
        self._show_decrypted_output = options.decrypted_output

        # requester signature for work order requests
        self._requester_signature = options.requester_signature

        logging.info("******* Hyperledger Avalon Generic client *******")

        # mode should be one of listing or registry (default)
        if self._mode == "registry" and self._address:
            logging.error("\n Worker registry contract"
                          " address is unsupported \n")
            sys.exit(-1)

    def _parse_command_line(self, args):
        parser = argparse.ArgumentParser()
        mutually_excl_group = parser.add_mutually_exclusive_group(
            required=True)
        parser.add_argument(
            "-c", "--config",
            help="The config file containing the "
                 "Ethereum contract information",
            type=str)
        mutually_excl_group.add_argument(
            "-u", "--uri",
            help="Direct API listener endpoint",
            type=str)
        mutually_excl_group.add_argument(
            "-a", "--address",
            help="an address (hex string) of the smart contract " +
            "(e.g. Worker registry listing)",
            type=str)
        mutually_excl_group.add_argument(
            "-b", "--blockchain",
            help="Blockchain type to use in proxy model",
            choices={"fabric", "ethereum"},
            type=str,
        )
        parser.add_argument(
            "-m", "--mode",
            help="should be one of listing or registry (default)",
            default="registry",
            choices={"registry", "listing"},
            type=str)
        parser.add_argument(
            "-t", "--attestation",
            help="should be one of attestation type [EPID/DCAP], "
            "defaults to EPID",
            default="EPID",
            choices={"EPID", "DCAP"},
            type=str)
        mutually_excl_group_worker = parser.add_mutually_exclusive_group()
        mutually_excl_group_worker.add_argument(
            "-w", "--worker_id",
            help="worker id in plain text to use to submit a work order",
            type=str)
        mutually_excl_group_worker.add_argument(
            "-wx", "--worker_id_hex",
            help="worker id as hex string to use to submit a work order",
            type=str)
        parser.add_argument(
            "-l", "--workload_id",
            help='workload id for a given worker',
            type=str)
        parser.add_argument(
            "-i", "--in_data",
            help='Input data',
            nargs="+",
            type=str)
        parser.add_argument(
            "-p", "--in_data_plain",
            help="Send input data as un-encrypted plain text",
            action='store_true')
        parser.add_argument(
            "-r", "--receipt",
            help="If present, retrieve and display work order receipt",
            action='store_true')
        parser.add_argument(
            "-o", "--decrypted_output",
            help="If present, display decrypted output as JSON",
            action='store_true')
        parser.add_argument(
            "-rs", "--requester_signature",
            help="Enable requester signature for work order requests",
            action="store_true")
        options = parser.parse_args(args)

        return options

    def _parse_config_file(self, config_file):
        # Parse config file and return a config dictionary.
        if config_file:
            conf_files = [config_file]
        else:
            conf_files = [TCF_HOME + "/sdk/avalon_sdk/tcf_connector.toml"]
        confpaths = ["."]
        try:
            config = pconfig.parse_configuration_files(conf_files, confpaths)
            json.dumps(config)
        except pconfig.ConfigurationException as e:
            logging.error(str(e))
            config = None

        return config

    def is_direct_mode(self):
        return self._is_direct_mode is True

    def get_config(self):
        return self._config

    def get_blockchain_type(self):
        return self._blockchain

    def get_worker_id(self):
        return self._worker_id

    def in_data_plain_text(self):
        return self._in_data_plain_text

    def show_receipt(self):
        return self._show_receipt

    def workload_id(self):
        return self._workload_id

    def in_data(self):
        return self._in_data

    def requester_signature(self):
        return self._requester_signature

    def show_decrypted_output(self):
        return self._show_decrypted_output

    def uri(self):
        return self._uri

    def mode(self):
        return self._mode

    def attestation_type(self):
        return self._attestation


def Main(args=None):
    parser = GenericClient(args)
    generic_client_obj = None
    if parser.is_direct_mode():
        generic_client_obj = DirectModelGenericClient(
            parser.get_config())
    elif parser.get_blockchain_type() in ["fabric", "ethereum"]:
        generic_client_obj = ProxyModelGenericClient(
            parser.get_config(),
            parser.get_blockchain_type())
    else:
        logging.error("Invalid inputs to generic client")
        sys.exit(-1)

    # Retrieve JSON RPC uri from registry list
    if not parser.uri() and parser.mode() == "listing":
        self._uri = self.retrieve_uri_from_registry_list(self._config)
    # Prepare worker
    worker_id = parser.get_worker_id()
    if worker_id is None:
        logging.error("worker id is missing")
        sys.exit(-1)

    if worker_id is None:
        logging.error("\n Unable to get worker {}\n".format(worker_id))
        sys.exit(-1)

    # Retrieve worker details
    worker_obj = generic_client_obj.get_worker_details(
        worker_id
    )
    if worker_obj is None:
        logging.error("Unable to retrieve worker details\n")
        sys.exit(-1)

    encrypt = worker_encrypt.WorkerEncrypt()
    # Create session key and iv to sign work order request
    session_key = encrypt.generate_session_key()
    session_iv = encrypt.generate_iv()

    # Do worker verification
    generic_client_obj.do_worker_verification(
        worker_obj, parser.attestation_type())

    logging.info("**********Worker details Updated with Worker ID" +
                 "*********\n%s\n", worker_id)

    # Create work order
    if parser.in_data_plain_text():
        # As per TC spec, if encryptedDataEncryptionKey is "-" then
        # input data is not encrypted
        encrypted_data_encryption_key = "-"
    else:
        # As per TC spec, if encryptedDataEncryptionKey is not
        # provided then set it to None which means
        # use default session key to encrypt input data
        encrypted_data_encryption_key = None

    code, wo_params = generic_client_obj.create_work_order_params(
        worker_id, parser.workload_id(),
        parser.in_data(),
        worker_obj.encryption_key,
        session_key, session_iv,
        encrypted_data_encryption_key)

    if not code:
        logging.error("Work order request creation failed \
                \n {}".format(wo_params))
        sys.exit(-1)

    if parser.requester_signature():
        # Add requester signature and requester verifying_key
        if wo_params.add_requester_signature() is False:
            logging.info("Work order request signing failed")
            sys.exit(-1)

    submit_status, wo_submit_res = generic_client_obj.submit_work_order(
        wo_params)

    if submit_status:
        # Create receipt
        if parser.show_receipt():
            generic_client_obj.create_work_order_receipt(
                wo_params,
                client_private_key)
        work_order_id = wo_params.get_work_order_id()
        # Retrieve work order result
        status, wo_res = generic_client_obj.get_work_order_result(
            work_order_id
        )

        # Check if result field is present in work order response
        if status:
            # Verify work order response signature
            if generic_client_obj.verify_wo_response_signature(
                    wo_res['result'],
                    worker_obj.verification_key,
                    wo_params.get_requester_nonce()
            ) is False:
                logging.error("Work order response signature"
                              " verification Failed")
                sys.exit(-1)
            # Decrypt work order response
            if parser.show_decrypted_output():
                decrypted_res = generic_client_obj.decrypt_wo_response(
                    wo_res['result'])
                logging.info("\nDecrypted response:\n {}".format(
                    decrypted_res))
        else:
            logging.error("\n Work order get result failed\n")
            sys.exit(-1)

        if parser.show_receipt():
            # Retrieve receipt
            retrieve_wo_receipt = \
                generic_client_obj.retrieve_work_order_receipt(
                    work_order_id)
            # Verify receipt signature
            if retrieve_wo_receipt:
                if "result" in retrieve_wo_receipt:
                    if generic_client_obj.verify_receipt_signature(
                            retrieve_wo_receipt) is False:
                        logging.error("Receipt signature verification Failed")
                        sys.exit(-1)
                else:
                    logging.info("Work Order receipt retrieve failed")
                    sys.exit(-1)
    else:
        logging.error("Work order submit failed {}".format(wo_submit_res))
        sys.exit(-1)


# -----------------------------------------------------------------------------
Main()
