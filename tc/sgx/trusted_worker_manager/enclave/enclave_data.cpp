/* Copyright 2019 Intel Corporation
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

#include "enclave_common_t.h"
#include "sgx_tseal.h"

#include <stdlib.h>
#include <string>
#include <vector>
#include <string.h>
#include<mbusafecrt.h>

#include "crypto.h"
#include "error.h"
#include "avalon_sgx_error.h"
#include "tcf_error.h"
#include "zero.h"
#include "enclave_utils.h"

#include "jsonvalue.h"
#include "parson.h"

#include "enclave_data.h"

// Below constants are the max limit for serialized version(base64 encoded)
// of private signature and private encryption keys
#define MAX_SERIALIZED_SIG_PRIV_KEY_SIZE 256
#define MAX_SERIALIZED_ENC_PRIV_KEY_SIZE 2048

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EnclaveData::EnclaveData(void) {
    // Do not attempt to catch errors here... let the calling procedure
    // handle the constructor errors

    // Generate private signing key
    private_signing_key_.Generate();

    // Create the public verifying key
    public_signing_key_ = private_signing_key_.GetPublicKey();

    // Generate private encryption key
    private_encryption_key_.Generate();

    // Create the public encryption key
    public_encryption_key_ = private_encryption_key_.GetPublicKey();

    // Create encryption key signature
    generate_encryption_key_signature();

    SerializePrivateData();
    SerializePublicData();
}
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EnclaveData::EnclaveData(const uint8_t* inSealedData) {
    tcf::error::ThrowIfNull(inSealedData, "Sealed sign up data pointer is NULL");
    uint32_t decrypted_size =
        sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(inSealedData));

    // Need to check for error
    std::vector<uint8_t> decrypted_data;
    decrypted_data.resize(decrypted_size);

    // Unseal the data
    sgx_status_t ret = sgx_unseal_data(reinterpret_cast<const sgx_sealed_data_t*>(inSealedData),
        nullptr, 0, &decrypted_data[0], &decrypted_size);
    tcf::error::ThrowSgxError(ret, "Failed to unseal  data");
    std::string decrypted_data_string(reinterpret_cast<const char*>(&decrypted_data[0]));
    DeserializePrivateData(decrypted_data_string);
    // Clear local variable storing secret(s)
    decrypted_data.clear();
    decrypted_data_string.clear();

    // Create encryption key signature
    generate_encryption_key_signature();

    SerializePrivateData();
    SerializePublicData();
}
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void EnclaveData::DeserializePrivateData(const std::string& inSerializedEnclaveData) {
    std::string svalue;
    const char* pvalue = nullptr;
    size_t pvalue_len = 0;

    // Parse the incoming enclave data
    JsonValue parsed(json_parse_string(inSerializedEnclaveData.c_str()));
    tcf::error::ThrowIfNull(parsed.value, "Failed to parse the Enclave data, badly formed JSON");

    JSON_Object* keystore_object = json_value_get_object(parsed);
    tcf::error::ThrowIfNull(keystore_object, "Failed to parse the key store object");

    // Public signing key
    pvalue = json_object_dotget_string(keystore_object, "SigningKey.PublicKey");
    tcf::error::ThrowIf<tcf::error::ValueError>(
        !pvalue, "Failed to retrieve public signing key from the key store");
    svalue.assign(pvalue);
    public_signing_key_.Deserialize(svalue);

    // Private signing key
    pvalue = json_object_dotget_string(keystore_object, "SigningKey.PrivateKey");
    tcf::error::ThrowIf<tcf::error::ValueError>(
        !pvalue, "Failed to retrieve private signing key from the key store");

    // Compute string length upto size of MAX_SERIALIZED_SIG_PRIV_KEY_SIZE
    pvalue_len = strnlen_s(pvalue, MAX_SERIALIZED_SIG_PRIV_KEY_SIZE);
    svalue.assign(pvalue);
    private_signing_key_.Deserialize(svalue);
    // Clear local variables storing secrets before re-assigning new value
    svalue.clear();
    memset_s((char*)pvalue, MAX_SERIALIZED_SIG_PRIV_KEY_SIZE, 0, pvalue_len);

    // Public encryption key
    pvalue = json_object_dotget_string(keystore_object, "EncryptionKey.PublicKey");
    tcf::error::ThrowIf<tcf::error::ValueError>(
        !pvalue, "Failed to retrieve public encryption key from the key store");

    svalue.assign(pvalue);
    public_encryption_key_.Deserialize(svalue);

    // Private encryption key
    pvalue = json_object_dotget_string(keystore_object, "EncryptionKey.PrivateKey");
    tcf::error::ThrowIf<tcf::error::ValueError>(
        !pvalue, "Failed to retrieve private encryption key from the key store");

    // Compute string length upto size of MAX_SERIALIZED_ENC_PRIV_KEY_SIZE
    pvalue_len = strnlen_s(pvalue, MAX_SERIALIZED_ENC_PRIV_KEY_SIZE);
    svalue.assign(pvalue);
    private_encryption_key_.Deserialize(svalue);
    // Clear local variables storing secrets before re-assigning new value
    svalue.clear();
    memset_s((char*)pvalue, MAX_SERIALIZED_ENC_PRIV_KEY_SIZE, 0, pvalue_len);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EnclaveData::~EnclaveData(void) {
    // Sanitizing class instance members other than below leads to enclave
    // crash hence avoid the sanitization.
    serialized_private_data_.clear();
    serialized_public_data_.clear();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void EnclaveData::SerializePrivateData(void) {
    JSON_Status jret;

    // Create serialized public data
    JsonValue dataValue(json_value_init_object());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        !dataValue.value, "Failed to create enclave data serialization object");

    JSON_Object* dataObject = json_value_get_object(dataValue);
    tcf::error::ThrowIfNull(dataObject, "Failed to retrieve serialization object");

    // Private signing key
    std::string b64_private_signing_key = private_signing_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_private_signing_key.empty(), "failed to serialize the private signing key");

    jret = json_object_dotset_string(
        dataObject, "SigningKey.PrivateKey", b64_private_signing_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on private signing key");

    // Sanitize local variables storing secrets
    b64_private_signing_key.clear();

    // Public signing key
    std::string b64_public_signing_key = public_signing_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_public_signing_key.empty(), "failed to serialize the public signing key");

    jret = json_object_dotset_string(
        dataObject, "SigningKey.PublicKey", b64_public_signing_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on public signing key");

    // Private encryption key
    std::string b64_private_encryption_key = private_encryption_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_private_encryption_key.empty(), "failed to serialize the private encryption key");

    jret = json_object_dotset_string(
        dataObject, "EncryptionKey.PrivateKey", b64_private_encryption_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on private encryption key");

    // Sanitize local variables storing secrets
    b64_private_encryption_key.clear();

    // Public encryption key
    std::string b64_public_encryption_key = public_encryption_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_public_encryption_key.empty(), "failed to serialize the public encryption key");

    jret = json_object_dotset_string(
        dataObject, "EncryptionKey.PublicKey", b64_public_encryption_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on public encryption key");

    // Sanitize local variables storing secrets
    b64_public_encryption_key.clear();

    size_t serializedSize = json_serialization_size(dataValue);

    std::vector<char> serialized_buffer;
    serialized_buffer.resize(serializedSize + 1);

    jret = json_serialize_to_buffer(dataValue, &serialized_buffer[0], serializedSize);
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed");

    serialized_private_data_.assign(&serialized_buffer[0]);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void EnclaveData::SerializePublicData(void) {
    JSON_Status jret;

    // Create serialized public data
    JsonValue dataValue(json_value_init_object());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        !dataValue.value, "Failed to create enclave data serialization object");

    JSON_Object* dataObject = json_value_get_object(dataValue);
    tcf::error::ThrowIfNull(dataObject, "Failed to retrieve serialization object");

    // Public signing key
    std::string b64_public_signing_key = public_signing_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_public_signing_key.empty(), "failed to serialize the public signing key");

    jret = json_object_dotset_string(dataObject, "VerifyingKey", b64_public_signing_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on public signing key");

    // Public encryption key
    std::string b64_public_encryption_key = public_encryption_key_.Serialize();
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        b64_public_encryption_key.empty(), "failed to serialize the public encryption key");

    jret =
        json_object_dotset_string(dataObject, "EncryptionKey", b64_public_encryption_key.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed on public encryption key");

    // Public encryption key signature
    jret =
        json_object_dotset_string(dataObject, "EncryptionKeySignature", \
            encryption_key_signature_.c_str());
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, \
        "enclave data serialization failed on public encryption key signature");

    size_t serializedSize = json_serialization_size(dataValue);

    std::vector<char> serialized_buffer;
    serialized_buffer.resize(serializedSize + 1);

    jret = json_serialize_to_buffer(dataValue, &serialized_buffer[0], serializedSize);
    tcf::error::ThrowIf<tcf::error::RuntimeError>(
        jret != JSONSuccess, "enclave data serialization failed");

    serialized_public_data_.assign(&serialized_buffer[0]);
}
