/* Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <vector>

#include "log.h"
#include "error.h"
#include "tcf_error.h"
#include "swig_utils.h"
#include "types.h"

#include "base.h"
#include "base_enclave_info.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool is_sgx_simulator() {
    return 0 != tcf::enclave_api::base::IsSgxSimulator();
}  // is_sgx_simulator

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void BaseEnclaveInfo::init_enclave_info(
    const std::string& enclave_module_path,
    const Attestation* attestation,
    const std::string& persisted_sealed_enclave_data,
    const int num_of_enclaves) {
    tcf::Log(TCF_LOG_INFO, "Initializing Avalon Intel SGX Enclave\n");
    tcf::Log(TCF_LOG_DEBUG, "Enclave path: %s\n", enclave_module_path.c_str());
    // tcf::Log(TCF_LOG_DEBUG, "SPID: %s\n", spid.c_str());

    tcf_err_t ret = tcf::enclave_api::base::Initialize(
        enclave_module_path, attestation,
        persisted_sealed_enclave_data, num_of_enclaves);
    ThrowTCFError(ret);
    tcf::Log(TCF_LOG_INFO, "Avalon Intel SGX Enclave initialized.\n");

    HexEncodedString mrEnclaveBuffer;
    HexEncodedString basenameBuffer;

    ThrowTCFError(
        tcf::enclave_api::base::GetEnclaveCharacteristics(
            mrEnclaveBuffer, basenameBuffer));

    this->mr_enclave = mrEnclaveBuffer;
    this->basename = basenameBuffer;

}  // BaseEnclaveInfo::init_enclave_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
BaseEnclaveInfo::~BaseEnclaveInfo() {
    try {
        tcf::enclave_api::base::Terminate();
        TerminateInternal();
    } catch (...) {}

}  // BaseEnclaveInfo::~BaseEnclaveInfo

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void BaseEnclaveInfo::TerminateEnclave() {
    try {
        tcf::Log(TCF_LOG_INFO, "Will terminate currently running enclave\n");
        tcf::enclave_api::base::Terminate();
    } catch (...) {
        tcf::Log(TCF_LOG_ERROR, "Error terminating Avalon Intel SGX Enclave\n");
    }
}  // BaseEnclaveInfo::TerminateEnclave
