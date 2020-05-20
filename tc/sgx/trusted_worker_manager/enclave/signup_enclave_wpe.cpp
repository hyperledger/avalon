/* Copyright 2020 Intel Corporation
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

#include "enclave_t.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_utils.h>
#include <sgx_quote.h>

#include "crypto.h"
#include "error.h"
#include "avalon_sgx_error.h"
#include "tcf_error.h"
#include "zero.h"
#include "jsonvalue.h"
#include "parson.h"
#include "hex_string.h"

#include "enclave_data.h"
#include "enclave_utils.h"
#include "signup_enclave_util.h"
#include "verify-report.h"


static void CreateReportDataWPE(const uint8_t* ext_data,
    std::string& enclave_encrypt_key,
    sgx_report_data_t* report_data);

static void CreateSignupReportDataWPE(const uint8_t* ext_data,
    EnclaveData* enclave_data,
    sgx_report_data_t* report_data);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t ecall_GenerateNonce(uint8_t* out_nonce, size_t in_nonce_size) {
    tcf_err_t result = TCF_SUCCESS;
    tcf::error::ThrowIf<tcf::error::ValueError>(in_nonce_size <= 0,
        "Nonce size should be positive value");
    try {
        ByteArray nonce_bytes = tcf::crypto::RandomBitString(in_nonce_size);
        // Convert nonce to hex string and persist in the EnclaveData
        EnclaveData* enclaveData = EnclaveData::getInstance();
        std::string nonce_hex = ByteArrayToHexEncodedString(nonce_bytes);
        enclaveData->set_nonce(nonce_hex);
        out_nonce = (uint8_t*) nonce_hex.c_str();
    } catch (tcf::error::ValueError& e) {
        Log(TCF_LOG_ERROR, "error::RandomNonce - %d - %s",
            e.error_code(), e.what());
        return TCF_ERR_CRYPTO;
    } catch (tcf::error::Error& e) {
        Log(TCF_LOG_ERROR, "error::RandomNonce - %d - %s\n",
            e.error_code(), e.what());
        return TCF_ERR_CRYPTO;
    } catch (...) {
        Log(TCF_LOG_ERROR, "error::RandomNonce - unknown internal error");
        return TCF_ERR_CRYPTO;
    }

    return result;
}  // ecall_GenerateNonce

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t ecall_CreateSignupDataWPE(const sgx_target_info_t* inTargetInfo,
    const uint8_t* inExtData,
    size_t inExtDataSize,
    const uint8_t* inExtDataSig,
    size_t inExtDataSigSize,
    const uint8_t* inKmeAttestation,
    size_t inKmeAttestationSize,
    char* outPublicEnclaveData,
    size_t inAllocatedPublicEnclaveDataSize,
    sgx_report_t* outEnclaveReport) {
    tcf_err_t result = TCF_SUCCESS;

    try {
        tcf::error::ThrowIfNull(inTargetInfo, "Target info pointer is NULL");
        tcf::error::ThrowIfNull(inExtData, "Extended data is NULL");
        tcf::error::ThrowIfNull(inExtDataSig,
            "Extended data signature input is NULL");
        tcf::error::ThrowIfNull(inExtDataSize, "Extended data size is NULL");
        tcf::error::ThrowIfNull(outPublicEnclaveData,
            "Public enclave data pointer is NULL");
        tcf::error::ThrowIfNull(outEnclaveReport,
            "Intel SGX report pointer is NULL");

        Zero(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize);

        // Get instance of enclave data
        EnclaveData* enclaveData = EnclaveData::getInstance();

        /*
           TODO: Implement Verify extended data signature using
           KME Verifying key
        */

        enclaveData->set_extended_data((const char*) inExtData);

        tcf::error::ThrowIf<tcf::error::ValueError>(
            inAllocatedPublicEnclaveDataSize < enclaveData->get_public_data_size(),
            "Public enclave data buffer size is too small");

        // Create the report data we want embedded in the enclave report.
        sgx_report_data_t reportData = {0};
        CreateSignupReportDataWPE(inExtData, enclaveData, &reportData);

        sgx_status_t ret = sgx_create_report(
            inTargetInfo, &reportData, outEnclaveReport);
        tcf::error::ThrowSgxError(ret, "Failed to create enclave report");
        // Give the caller a copy of the signing and encryption keys
        strncpy_s(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize,
            enclaveData->get_public_data().c_str(),
            enclaveData->get_public_data_size());

    } catch (tcf::error::Error& e) {
        SAFE_LOG(TCF_LOG_ERROR,
            "Error in Avalon enclave(ecall_CreateSignupDataWPE): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        SAFE_LOG(TCF_LOG_ERROR,
            "Unknown error in Avalon enclave(ecall_CreateSignupDataWPE)");
        result = TCF_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CreateSignupDataWPE

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void CreateSignupReportDataWPE(const uint8_t* ext_data,
    EnclaveData* enclave_data, sgx_report_data_t* report_data) {

    // We will put the following in the report data
    // WPE_ENCLAVE:  REPORT_DATA[0:31] - PUB ENC KEY
    //               REPORT_DATA[32:63] - EXT DATA where EXT_DATA contains
    //               verification key generated by KME
    
    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
    //
    // If anything in this code changes the way in which the actual enclave
    // report data is represented, the corresponding code that verifies
    // the report data has to be change accordingly.
    //
    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING

    std::string enclave_encrypt_key = \
        enclave_data->get_serialized_encryption_key();

    // NOTE - we are putting the hash directly into the report
    // data structure because it is (64 bytes) larger than the SHA256
    // hash (32 bytes) but we zero it out first to ensure that it is
    // padded with known data.

    Zero(report_data, sizeof(*report_data));

    uint8_t enc_key_hash[SGX_HASH_SIZE] = {0};
    uint8_t ext_data_hash[SGX_HASH_SIZE] = {0};
    ComputeSHA256Hash(enclave_encrypt_key, enc_key_hash);
    ComputeSHA256Hash((const char*) ext_data, ext_data_hash);

    // Concatenate hash of public encryption key and hash of extended data
    strncpy((char*)report_data->d,
        (const char*) enc_key_hash, SGX_HASH_SIZE);
    strncat((char*)report_data->d,
        (const char*) ext_data_hash, SGX_HASH_SIZE);
}  // CreateSignupReportDataWPE

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
tcf_err_t ecall_VerifyEnclaveInfoWPE(const char* enclave_info,
    const char* mr_enclave, const uint8_t* ext_data) {

    tcf_err_t result = TCF_SUCCESS;

    // Parse the enclave_info
    JsonValue enclave_info_parsed(json_parse_string(enclave_info));
    tcf::error::ThrowIfNull(enclave_info_parsed.value,
        "Failed to parse the enclave info, badly formed JSON");

    JSON_Object* enclave_info_object = \
        json_value_get_object(enclave_info_parsed);
    tcf::error::ThrowIfNull(enclave_info_object,
        "Invalid enclave_info, expecting object");

    const char* svalue = nullptr;
    svalue = json_object_dotget_string(enclave_info_object, "verifying_key");
    tcf::error::ThrowIfNull(svalue, "Invalid verifying_key");
    std::string enclave_id(svalue);

    svalue = json_object_dotget_string(enclave_info_object, "encryption_key");
    tcf::error::ThrowIfNull(svalue, "Invalid encryption_key");
    std::string enclave_encrypt_key(svalue);

    // Parse proof data
    svalue = json_object_dotget_string(enclave_info_object, "proof_data");
    std::string proof_data(svalue);
    JsonValue proof_data_parsed(json_parse_string(proof_data.c_str()));
    tcf::error::ThrowIfNull(proof_data_parsed.value,
        "Failed to parse the proofData, badly formed JSON");
    JSON_Object* proof_object = json_value_get_object(proof_data_parsed);
    tcf::error::ThrowIfNull(proof_object, "Invalid proof, expecting object");

    svalue = json_object_dotget_string(proof_object, "ias_report_signature");
    tcf::error::ThrowIfNull(svalue, "Invalid proof_signature");
    const std::string proof_signature(svalue);

    //Parse verification report
    svalue = json_object_dotget_string(proof_object, "verification_report");
    tcf::error::ThrowIfNull(svalue, "Invalid proof_verification_report");
    const std::string verification_report(svalue);

    JsonValue verification_report_parsed(
        json_parse_string(verification_report.c_str()));
    tcf::error::ThrowIfNull(verification_report_parsed.value,
        "Failed to parse the verificationReport, badly formed JSON");

    JSON_Object* verification_report_object = \
        json_value_get_object(verification_report_parsed);
    tcf::error::ThrowIfNull(verification_report_object,
        "Invalid verification_report, expecting object");

    svalue = json_object_dotget_string(verification_report_object,
        "isvEnclaveQuoteBody");
    tcf::error::ThrowIfNull(svalue, "Invalid enclave_quote_body");
    const std::string enclave_quote_body(svalue);

    svalue = json_object_dotget_string(
        verification_report_object, "epidPseudonym");
    tcf::error::ThrowIfNull(svalue, "Invalid epid_pseudonym");
    const std::string epid_pseudonym(svalue);

    // Verify verification report signature
    // Verify good quote, but group-of-date is not considered ok
    bool r = verify_enclave_quote_status(verification_report.c_str(),
        verification_report.length(), 1);
    tcf::error::ThrowIf<tcf::error::ValueError>(
        r!=true, "Invalid Enclave Quote:  group-of-date NOT OKAY");

    const char* ias_report_cert = json_object_dotget_string(
        proof_object, "ias_report_signing_certificate");

    std::vector<char> verification_report_vec(
        verification_report.begin(), verification_report.end());
    verification_report_vec.push_back('\0');
    char* verification_report_arr = &verification_report_vec[0];

    std::vector<char> proof_signature_vec(proof_signature.begin(),
        proof_signature.end());
    proof_signature_vec.push_back('\0');
    char* proof_signature_arr = &proof_signature_vec[0];

    //verify IAS signature
    r = verify_ias_report_signature(ias_report_cert,
                                    verification_report_arr,
                                    strlen(verification_report_arr),
                                    proof_signature_arr,
                                    strlen(proof_signature_arr));
    tcf::error::ThrowIf<tcf::error::ValueError>(
    r!=true, "Invalid verificationReport; Invalid Signature");

    // Extract ReportData and MR_ENCLAVE from isvEnclaveQuoteBody
    // present in Verification Report
    sgx_quote_t* quote_body = reinterpret_cast<sgx_quote_t*>(
        Base64EncodedStringToByteArray(enclave_quote_body).data());
    sgx_report_body_t* report_body = &quote_body->report_body;
    sgx_report_data_t expected_report_data = *(&report_body->report_data);
    sgx_measurement_t mr_enclave_from_report = *(&report_body->mr_enclave);
    sgx_basename_t mr_basename_from_report = *(&quote_body->basename);

    ByteArray mr_enclave_bytes = HexEncodedStringToByteArray(mr_enclave);
    //CHECK MR_ENCLAVE
    tcf::error::ThrowIf<tcf::error::ValueError>(
        memcmp(mr_enclave_from_report.m, mr_enclave_bytes.data(),
            SGX_HASH_SIZE)  != 0, "Invalid MR_ENCLAVE");

    // Verify Report Data by comparing hash of report data in
    // Verification Report with computed report data
    sgx_report_data_t computed_report_data = {0};
    CreateReportDataWPE(ext_data,
        enclave_encrypt_key, &computed_report_data);

    //Compare computedReportData with expectedReportData
    tcf::error::ThrowIf<tcf::error::ValueError>(
        memcmp(computed_report_data.d, expected_report_data.d,
        SGX_REPORT_DATA_SIZE)  != 0,
        "Invalid Report data: computedReportData does not match expectedReportData");
    return result;
}  // ecall_VerifyEnclaveInfoWPE

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void CreateReportDataWPE(const uint8_t* ext_data,
    std::string& enclave_encrypt_key,
    sgx_report_data_t* report_data) {
    // We will put the following in the report data
    // WPE_ENCLAVE:  REPORT_DATA[0:31] - PUB ENC KEY
    //               REPORT_DATA[32:63] - EXT DATA where EXT_DATA contains
    //               verification key generated by KME

    // NOTE - we are putting the hash directly into the report
    // data structure because it is (64 bytes) larger than the SHA256
    // hash (32 bytes) but we zero it out first to ensure that it is
    // padded with known data.

    Zero(report_data, sizeof(*report_data));

    uint8_t enc_key_hash[SGX_HASH_SIZE] = {0};
    uint8_t ext_data_hash[SGX_HASH_SIZE] = {0};
    ComputeSHA256Hash(enclave_encrypt_key, enc_key_hash);
    ComputeSHA256Hash((const char*) ext_data, ext_data_hash);

    // Concatenate hash of public encryption key and hash of extended data
    strncpy((char*)report_data->d,
        (const char*) enc_key_hash, SGX_HASH_SIZE);
    strncat((char*)report_data->d,
        (const char*) ext_data_hash, SGX_HASH_SIZE);
}  // CreateReportDataWPE
