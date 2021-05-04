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

#include <algorithm>
#include <string>
#include <vector>

#include "crypto.h"
#include "error.h"
#include "hex_string.h"
#include "log.h"
#include "tcf_error.h"
#include "types.h"

#include "enclave.h"
#include "base.h"

static bool g_IsInitialized = false;
static std::string g_LastError;
static tcf::enclave_queue::EnclaveQueue *g_EnclaveReadyQueue;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int tcf::enclave_api::base::IsSgxSimulator() {
#if defined(SGX_SIMULATOR)
#if SGX_SIMULATOR == 1
    return 1;
#else  // SGX_SIMULATOR not 1
    return 0;
#endif  //  #if SGX_SIMULATOR == 1
#else  // SGX_SIMULATOR not defined
    return 0;
#endif  // defined(SGX_SIMULATOR)
}  // tcf::enclave_api::base::IsSgxSimulator


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf::enclave_queue::ReadyEnclave tcf::enclave_api::base::GetReadyEnclave() {
    return tcf::enclave_queue::ReadyEnclave(g_EnclaveReadyQueue);
}  // tcf::enclave_api::base::GetReadyEnclaveIndex


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void tcf::enclave_api::base::SetLastError(
    const std::string& message) {
    g_LastError = message;
}  // tcf::enclave_api::base::SetLastError

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string tcf::enclave_api::base::GetLastError(void) {
    return g_LastError;
}  // tcf::enclave_api::base::GetLastErrorMessage

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t tcf::enclave_api::base::Initialize(
    const std::string& inPathToEnclave,
    const Attestation *attestation,
    const std::string& persisted_sealed_data,
    const int numOfEnclaves) {
    tcf_err_t ret = TCF_SUCCESS;

    try {
        if (!g_IsInitialized) {

            if (g_EnclaveReadyQueue == NULL) g_EnclaveReadyQueue = new tcf::enclave_queue::EnclaveQueue();

            g_Enclave.reserve(numOfEnclaves);
            for (int i = 0; i < numOfEnclaves; ++i) {
                g_Enclave.push_back(tcf::enclave_api::Enclave(attestation));
                g_EnclaveReadyQueue->push(i);
            }

            for (tcf::enclave_api::Enclave& enc : g_Enclave) {
                enc.Load(inPathToEnclave, persisted_sealed_data);
            }

            g_IsInitialized = true;
        }
    } catch (tcf::error::Error& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch(std::exception& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = TCF_ERR_UNKNOWN;
    } catch(...) {
        tcf::enclave_api::base::SetLastError("Unexpected exception");
        ret = TCF_ERR_UNKNOWN;
    }

    return ret;
}  // tcf::enclave_api::base::Initialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t tcf::enclave_api::base::Terminate() {
    // Unload the enclave
    tcf_err_t ret = TCF_SUCCESS;

    try {
        if (g_IsInitialized) {
            for (tcf::enclave_api::Enclave& enc : g_Enclave) {
                enc.Unload();
            }
            // Empty out the vector of enclaves maintained
            int q_size = g_Enclave.size();
            for (int i=0; i< q_size; i++){
                g_Enclave.pop_back();
                g_EnclaveReadyQueue->pop();
            }
            //g_Enclave.clear();
            g_IsInitialized = false;
        }
    } catch (tcf::error::Error& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = TCF_ERR_UNKNOWN;
    } catch (...) {
        tcf::enclave_api::base::SetLastError("Unexpected exception");
        ret = TCF_ERR_UNKNOWN;
    }

    return ret;
}  // tcf::enclave_api::base::Terminate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t tcf::enclave_api::base::GetEnclaveQuoteSize() {
    return g_Enclave[0].GetQuoteSize();
}  // tcf::enclave_api::base::GetEnclaveQuoteSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t tcf::enclave_api::base::GetSignatureSize() {
    // This is the size of the byte array required for the signature.
    // Fixed constant for now until there is one we can get from the
    // crypto library.
    return tcf::crypto::constants::MAX_SIG_SIZE;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t tcf::enclave_api::base::GetEnclaveCharacteristics(
    HexEncodedString& outMrEnclave,
    HexEncodedString& outEnclaveBasename) {
    tcf_err_t ret = TCF_SUCCESS;

    try {
        // Get the enclave characteristics and then convert the binary data to
        // hex strings and copy them to the caller's buffers.
        sgx_measurement_t enclaveMeasurement;
        sgx_basename_t enclaveBasename;

        g_Enclave[0].GetEnclaveCharacteristics(
            &enclaveMeasurement,
            &enclaveBasename);

        outMrEnclave = tcf::BinaryToHexString(
            enclaveMeasurement.m,
            sizeof(enclaveMeasurement.m));

        outEnclaveBasename = tcf::BinaryToHexString(
            enclaveBasename.name,
            sizeof(enclaveBasename.name));

    } catch (tcf::error::Error& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        tcf::enclave_api::base::SetLastError(e.what());
        ret = TCF_ERR_UNKNOWN;
    } catch (...) {
        tcf::enclave_api::base::SetLastError("Unexpected exception");
        ret = TCF_ERR_UNKNOWN;
    }

    return ret;
}  // tcf::enclave_api::base::GetEnclaveCharacteristics

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
