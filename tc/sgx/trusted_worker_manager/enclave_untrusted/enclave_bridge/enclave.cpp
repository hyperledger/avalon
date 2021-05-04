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

#include <linux/limits.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <pthread.h>

#include "sgx_support.h"
#include "enclave_common_u.h"

#include "log.h"

#include "error.h"
#include "avalon_sgx_error.h"
#include "hex_string.h"
#include "tcf_error.h"
#include "types.h"
#include "sgx_utility.h"

#include "enclave.h"

std::vector<tcf::enclave_api::Enclave> g_Enclave;

namespace tcf {

    namespace enclave_api {

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        // XX External interface                                     XX
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        Enclave::Enclave(const Attestation *attestation_obj) :
            attestation(const_cast<Attestation *>(attestation_obj)) {
        }  // Enclave::Enclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        Enclave::~Enclave() {
            try {
                this->Unload();
            } catch (error::Error& e) {
                /*tcf::logger::LogV(
                    TCF_LOG_ERROR,
                    "Error unloading Avalon enclave: %04X -- %s",
                    e.error_code(),
                    e.what());*/
            } catch (...) {
                tcf::Log(
                    TCF_LOG_ERROR,
                    "Unknown error unloading Avalon enclave\n");
            }
        }  // Enclave::~Enclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::Load(
            const std::string& inEnclaveFilePath,
            const Base64EncodedString& inSealedEnclaveData) {
            tcf::error::ThrowIf<tcf::error::ValueError>(
                inEnclaveFilePath.empty() ||
                inEnclaveFilePath.length() > PATH_MAX,
                "Invalid enclave path.");

            this->Unload();
            this->enclaveFilePath = inEnclaveFilePath;
            this->LoadEnclave(inSealedEnclaveData);
        }  // Enclave::Load

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::Unload() {
            if (this->enclaveId) {
                // No power or busy retries here....
                // We don't want to reinitialize just to shutdown.
                if (SGX_SUCCESS != sgx_destroy_enclave(this->enclaveId))
                    tcf::Log(TCF_LOG_ERROR,"Enclave destroy failed.\n");
                this->enclaveId = 0;
            }
        }  // Enclave::Unload

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetEnclaveCharacteristics(
            sgx_measurement_t* outEnclaveMeasurement,
            sgx_basename_t* outEnclaveBasename) {
            tcf::error::ThrowIf<tcf::error::ValueError>(
                this->attestation == nullptr,
                "Attestation object is not initialized"
            );
	    tcf_err_t tcfRet = this->attestation->GetEnclaveCharacteristics(this->enclaveId,
			                                 outEnclaveMeasurement,
				                         outEnclaveBasename);
	    this->ThrowTCFError(tcfRet);
        }  // Enclave::GetEnclaveCharacteristics

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::CreateQuoteFromReport(
            const sgx_report_t* inEnclaveReport,
            ByteArray& outEnclaveQuote) {
	    tcf::error::ThrowIf<tcf::error::ValueError>(
		this->attestation == nullptr,
		"Attestation object is not initialized"
	    );
	    this->attestation->CreateQuoteFromReport(inEnclaveReport, outEnclaveQuote);
        }  // Enclave::GenerateSignupData


        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        // XX Private helper methods                                 XX
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::ThrowTCFError(
            tcf_err_t err) {
            if (err != TCF_SUCCESS) {
                std::string tmp(this->enclaveError);
                this->enclaveError.clear();
                throw error::Error(err, tmp.c_str());
            }
        }  // Enclave::ThrowTCFError

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::LoadEnclave(
                const Base64EncodedString& persistedSealedEnclaveData) {
            if (!this->enclaveId) {
                /* Enclave id, used in communicating with enclave */
                Enclave::QuerySgxStatus();

                sgx_launch_token_t token = { 0 };
                int flags = SGX_DEBUG_FLAG;
                tcf::error::ThrowSgxError((SGX_DEBUG_FLAG == 0 ?
                    SGX_ERROR_UNEXPECTED:SGX_SUCCESS),
                    "Intel SGX DEBUG flag is 0"
                    " (possible cause: wrong compile flags)");

                // First attempt to load the enclave executable
                sgx_status_t ret = SGX_SUCCESS;
                ret = tcf::sgx_util::CallSgx([this, flags, &token] () {
                        int updated = 0;
                        return sgx_create_enclave(
                            this->enclaveFilePath.c_str(),
                            flags,
                            &token,
                            &updated,
                            &this->enclaveId,
                            NULL);
                    },
                    10,  // retries
                    250  // retryWaitMs
                    );
                tcf::error::ThrowSgxError(ret, "Unable to create enclave.");
                // Initialize the enclave
                tcf_err_t tcfError = TCF_SUCCESS;

                ByteArray persistedSealedData = \
                    Base64EncodedStringToByteArray(persistedSealedEnclaveData);
                ret = tcf::sgx_util::CallSgx([
                            this,
                            &tcfError,
                            &persistedSealedData] () {
                        sgx_status_t ret =
                        ecall_Initialize(
                            this->enclaveId,
                            &tcfError,
                            persistedSealedData.data(),
                            persistedSealedData.size()
                        );
                        return error::ConvertErrorStatus(ret, tcfError);
                    });
                tcf::error::ThrowSgxError(ret, "Enclave call to ecall_Initialize failed");
                this->ThrowTCFError(tcfError);

                // We need to figure out a priori the size of the sealed signup
                // data so that caller knows the proper size for the buffer when
                // creating signup data.
                ret = tcf::sgx_util::CallSgx([this, &tcfError] () {
                            sgx_status_t ret =
                            ecall_CalculateSealedEnclaveDataSize(
                                this->enclaveId,
                                &tcfError,
                                &this->sealedSignupDataSize);
                            return
                            error::ConvertErrorStatus(ret, tcfError);
                        });
                tcf::error::ThrowSgxError(
                    ret,
                    "Failed to calculate length of sealed signup data");
                this->ThrowTCFError(tcfError);
            }
        }  // Enclave::LoadEnclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        /* This function is run as the very first step in the attestation
           process to check the device status; query the status of the
           Intel SGX device. If not enabled before, enable it.
           If the device is not enabled, Intel SGX device not found error
           is expected when the enclave is created.
        */
        void Enclave::QuerySgxStatus() {
            sgx_device_status_t sgx_device_status;
            sgx_status_t ret = sgx_enable_device(&sgx_device_status);
            tcf::error::ThrowSgxError(ret);

            switch (sgx_device_status) {
            case SGX_ENABLED:
                break;
            case SGX_DISABLED_REBOOT_REQUIRED:
                throw tcf::error::RuntimeError(
                    "Intel SGX device will be enabled after this machine is "
                    "rebooted.\n");
                break;
            case SGX_DISABLED_LEGACY_OS:
                throw tcf::error::RuntimeError(
                    "Intel SGX device can't be enabled on an OS that doesn't "
                    "support EFI interface.\n");
                break;
            case SGX_DISABLED:
                throw tcf::error::RuntimeError("Intel SGX device not found.\n");
                break;
            default:
                throw tcf::error::RuntimeError("Unexpected error.\n");
                break;
            }
        }  // Enclave::QuerySgxStatus

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        /* Initialize the quote by calling sgx sdk API */
        void Enclave::InitQuote(sgx_target_info_t& target_info) {
            this->attestation->InitQuote(target_info);
        } // Enclave::InitQuote

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#ifdef BUILD_SINGLETON
        tcf_err_t Enclave::VerifyEnclaveInfoSingleton(
            const std::string& enclave_info,
            const std::string& mr_enclave,
            const sgx_enclave_id_t& enclave_id) {
            return this->attestation->VerifyEnclaveInfoSingleton(enclave_info,
                mr_enclave, enclave_id);
        }
#elif BUILD_KME
        tcf_err_t Enclave::VerifyEnclaveInfoKME(
	    const std::string& enclave_info,
            const std::string& mr_enclave,
            const std::string& ext_data,
            const sgx_enclave_id_t& enclave_id) {
            return this->attestation->VerifyEnclaveInfoKME(enclave_info, mr_enclave,
                ext_data, enclave_id);
        }
#elif BUILD_WPE
        tcf_err_t Enclave::VerifyEnclaveInfoWPE(
	    const std::string& enclave_info,
            const std::string& mr_enclave,
            const std::string& ext_data,
            const sgx_enclave_id_t& enclave_id) {
            return this->attestation->VerifyEnclaveInfoWPE(enclave_info, mr_enclave,
                ext_data, enclave_id);
        }
#endif
    }  // namespace enclave_api
}  // namespace tcf
