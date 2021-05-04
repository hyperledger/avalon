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

#include "utils.h"
#include "kme_workload_plug-in.h"
#include "enclave_data.h"
#include "error.h"
#include "parson.h"
#include "jsonvalue.h"
#include "json_utils.h"
#include "signup_enclave_util.h"
#include "enclave_utils.h"
#include "crypto.h"
#include "hex_string.h"
#include <stdint.h>

using namespace tcf::error;
#define KME_STATE_UPDATE_UID_SIZE_BYTES 16

REGISTER_WORKLOAD_PROCESSOR_KME("kme",KMEWorkloadProcessor);


/*
 *  Generates verification key, verification key signature and
 *  add them to output data.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
 *  @param ext_wo_info_kme - Instance of KMEs extended work order implementation
*/

/* Map of key: Hex of public verification key or unique ID
 * value: private key corresponding to unique ID or verification key */
std::map<ByteArray, ByteArray> KMEWorkloadProcessor::sig_key_map;
/* Map of key: WPE encryption public key and value: private
 * key of unique ID verification key
 */
std::map<ByteArray, WPEInfo> KMEWorkloadProcessor::wpe_enc_key_map;

/*
* State_uid persisted from last call to state_uid from a replica KME.
* @TODO - Might need to be converted to a map for handling multiple
* replica KME spawning/syncing simultaneously
*/
std::string state_uid_hex;

/*
* State request nonce persisted from last call to state_request from
* a replica KME. Used to check freshness when set-state call arrives.
* @TODO - Might need to be converted to a map for handling multiple
* replica KME spawning/syncing simultaneously
*/
std::string state_req_nonce_hex;

WPEInfo::WPEInfo() {
    workorder_count = 0;
    signing_key = {};
}

WPEInfo::WPEInfo(const ByteArray& _sk) {
    workorder_count = 0;
    /* signing key corresponds to the private key of
     * unique ID verification key */
    signing_key = _sk;
}

WPEInfo::WPEInfo(const uint64_t _wo_c, const ByteArray& _sk) {
    workorder_count = _wo_c;
    /* signing key corresponds to the private key of
     * unique ID verification key */
    signing_key = _sk;
}

/*
 *  Get Unique ID for the KME State Update.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
 *
 *  Outdata contains the following -
 *  uid_ba - Unique id for replication as ByteArray
*/
void KMEWorkloadProcessor::GetStateReplicationId(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    // Generate random bytes of size 16,
    ByteArray uid_bytes = tcf::crypto::RandomBitString(KME_STATE_UPDATE_UID_SIZE_BYTES);
    // Convert nonce to hex string
    std::string uid_hex = ByteArrayToHexEncodedString(uid_bytes);

    // Persist the state_uid in-memory
    state_uid_hex = uid_hex;

    ByteArray uid_ba = StrToByteArray(uid_hex);

    SetStatus(KME_REPL_OP_SUCCESS, out_work_order_data);
    AddOutput(1, uid_ba, out_work_order_data);
}

/*
 *  Create KME State Update Request.
 *
 *  @param in_work_order_data - vector of work order indata.
 *         It consists of the unique_id and signing key
 *  @param out_work_order_data - vector of work order outdata
 *
 *  Outdata contains the following -
 *  uid_ba - Unique id for replication as ByteArray
 *  nonce_ba - A random nonce as ByteArray
 *  uid_nonce_signed - Signatue (using private signing key of Replica KME)
 *                     of the concatenation of uid & nonce
*/
void KMEWorkloadProcessor::CreateStateReplicatonRequest(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    // Extract uid from in_data that comes in the request from
    // replica KME
    ByteArray uid_ba = in_work_order_data[0].decrypted_data;
    // Generate random bytes of size 16,
    ByteArray nonce_bytes = tcf::crypto::RandomBitString(16);
    // Convert nonce to hex string
    std::string nonce_hex = ByteArrayToHexEncodedString(nonce_bytes);
    // Persist the state_req_nonce_hex in-memory to later verify freshness
    // of set-state request in a replica KME
    state_req_nonce_hex = nonce_hex;

    ByteArray nonce_ba = StrToByteArray(state_req_nonce_hex);
    SetStatus(KME_REPL_OP_SUCCESS, out_work_order_data);
    AddOutput(1, uid_ba, out_work_order_data); // unique_id_hex_str
    AddOutput(2, nonce_ba, out_work_order_data); // generated_nonce_hex_str
    ByteArray concat_ba = StrToByteArray( ByteArrayToStr(uid_ba)
                                        + ByteArrayToStr(nonce_ba));
    uint8_t concat_str_hash[SGX_HASH_SIZE] = {0};
    ComputeSHA256Hash(ByteArrayToString(concat_ba), concat_str_hash);
    EnclaveData* enclave_data = EnclaveData::getInstance();
    ByteArray uid_nonce_signed = enclave_data->sign_message(
        ByteArray(std::begin(concat_str_hash), std::end(concat_str_hash)));
    uid_nonce_signed = StrToByteArray(ByteArrayToHexEncodedString(uid_nonce_signed));
    AddOutput(3, uid_nonce_signed, out_work_order_data); // uid_nonce_signed
}

/*
 *  Get Primary KME State API.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
 *
 *  Outdata contains the following -
 *  unique_id_hex - Unique id for replication as ByteArray
 *  generated_nonce_hex - Generated nonce
 *  enc_sym_key - Encrypted (using pub encryption key of replica KME)
 *                symmetric key
 *  enc_state_data - Encrypted (using symmetric key) state data
 *  hash_signed - Hash of state data, symmetric key, unique id, nonce
 *                is hashed and then signed using the private signing
 *                key of the primary KME
*/
void KMEWorkloadProcessor::GetStateReplica(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    // Extract attestation_info from in_data at index 0
    ByteArray attestation_info = in_work_order_data[0].decrypted_data;
    // Extract unique_id_hex from in_data at index 1
    ByteArray unique_id_hex = in_work_order_data[1].decrypted_data;
    // Extract generated_nonce_hex from in_data at index 2
    ByteArray generated_nonce_hex = in_work_order_data[2].decrypted_data;
    // Extract uid_nonce_sig from in_data at index 3
    ByteArray uid_nonce_sig = in_work_order_data[3].decrypted_data;
    // Extract replica KME pub signing key from in_data that comes in
    // the request
    ByteArray pub_sig_key_ba = in_work_order_data[4].decrypted_data;
    // Extract replica KME pub enc key from in_data that comes in
    // the request
    ByteArray pub_enc_key_ba = in_work_order_data[5].decrypted_data;

    //@TODO - Verify attestation_info; MRSIGNER & MRENCLAVE should match for the
    //requesting & primary KME.

    //Verify that the unique_id matches the one in-memory
    if (memcmp(unique_id_hex.data(),
            StrToByteArray(state_uid_hex).data(), 16) != 0) {
        this->SetStatus((int)ERR_KME_REPL_UID_MISMATCH, out_work_order_data);
        ThrowIf<ValueError>(true, "State uid did not match");
    }

    //Verfiy signature
    tcf::crypto::sig::PublicKey pub_sk = tcf::crypto::sig::PublicKey(ByteArrayToStr(pub_sig_key_ba));

    ByteArray concat_ba = StrToByteArray( ByteArrayToStr(unique_id_hex)
                                        + ByteArrayToStr(generated_nonce_hex));
    uint8_t concat_str_hash[SGX_HASH_SIZE] = {0};
    ComputeSHA256Hash(ByteArrayToString(concat_ba), concat_str_hash);
    uid_nonce_sig = HexEncodedStringToByteArray(ByteArrayToStr(uid_nonce_sig));
    if (pub_sk.VerifySignature(ByteArray(std::begin(concat_str_hash),
                                         std::end(concat_str_hash)),
                               uid_nonce_sig) != 1) {
        this->SetStatus((int)ERR_KME_REPL_SIG_VERIF_FAILED, out_work_order_data);
        ThrowIf<ValueError>(true, "Signature verification failed while getting state.");
    }
    //Generate Symmetric enc key
    ByteArray sym_key = tcf::crypto::skenc::GenerateKey();

    EnclaveData* enclave_data = EnclaveData::getInstance();
    //Obtain state data. String concatenation of pvt_data, enc_key_map, sig_key_map
    //delimited by semicolon (;)
    std::string state_data = enclave_data->get_private_data();
    state_data += ";";
    state_data += KMEWorkloadProcessor::serializeEncKeyMap();
    state_data += ";";
    state_data += KMEWorkloadProcessor::serializeSigKeyMap();

    ByteArray state_data_ba = StrToByteArray(state_data);
    //Encrypt state data with sym enc key
    ByteArray enc_state_data = tcf::crypto::skenc::EncryptMessage(
                                   sym_key, state_data_ba);
    //Encrypt sym enc key with requester pub enc key
    tcf::crypto::pkenc::PublicKey pub_ek = tcf::crypto::pkenc::PublicKey(ByteArrayToStr(pub_enc_key_ba));
    ByteArray enc_sym_key = pub_ek.EncryptMessage(sym_key);

    //Generate signature of the output

    //SHA256 of state data(JSON as byte array) is calculated
    ComputeSHA256Hash(ByteArrayToString(state_data_ba), concat_str_hash);

    //Concatenate hash, sym enc key, unique id, nonce
    concat_ba = StrToByteArray( ByteArrayToStr(ByteArray(std::begin(concat_str_hash),
                                               std::end(concat_str_hash)))
                                + ByteArrayToStr(sym_key)
                                + ByteArrayToStr(unique_id_hex)
                                + ByteArrayToStr(generated_nonce_hex));

    //SHA256 of concatenated byte array is calculated
    ComputeSHA256Hash(ByteArrayToString(concat_ba), concat_str_hash);

    //Sign hash with signing key
    ByteArray hash_signed = enclave_data->sign_message(
        ByteArray(std::begin(concat_str_hash), std::end(concat_str_hash)));

    //Cleanup in-memory state-uid
    state_uid_hex = "";

    SetStatus(KME_REPL_OP_SUCCESS, out_work_order_data);
    //@TODO - Output at index 1 to be Attestation info of this(primary) KME
    AddOutput(1, unique_id_hex, out_work_order_data); // unique_id_hex_str
    AddOutput(2, generated_nonce_hex, out_work_order_data); // generated_nonce_hex_str
    AddOutput(3, enc_sym_key, out_work_order_data); // Encrypted symmetric key
    AddOutput(4, enc_state_data, out_work_order_data); // Encrypted state data
    AddOutput(5, hash_signed, out_work_order_data); // Signed hash
}

/*
 *  Set Backup KME State.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
 *
 *  Outdata contains the following -
 *  sealed_ba - Sealed data as ByteArray
*/
void KMEWorkloadProcessor::UpdateState(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {


    // Extract attestation_info from in_data at index 0
    ByteArray attestation_info = in_work_order_data[0].decrypted_data;
    // Extract unique_id_hex from in_data at index 1
    ByteArray unique_id_hex = in_work_order_data[1].decrypted_data;
    // Extract generated_nonce_hex from in_data at index 2
    ByteArray generated_nonce_hex = in_work_order_data[2].decrypted_data;
    // Extract enc_sym_key from in_data at index 3
    ByteArray enc_sym_key = in_work_order_data[3].decrypted_data;
    // Extract enc_state_data from in_data at index 4
    ByteArray enc_state_data = in_work_order_data[4].decrypted_data;
    // Extract output_sig from in_data at index 5
    ByteArray output_sig = in_work_order_data[5].decrypted_data;

    EnclaveData* enclave_data = EnclaveData::getInstance();

    //@TODO - Verify that attestation attributes match with primary KME
    //Verify that input nonce matches with that in-memory
    if (memcmp(generated_nonce_hex.data(),
            StrToByteArray(state_req_nonce_hex).data(), 16) != 0) {
        this->SetStatus((int)ERR_KME_REPL_NONCE_MISMATCH, out_work_order_data);
        ThrowIf<ValueError>(true, "Generated nonce did not match");
    }
    //Verify signature

    //Decrypt state that was encrypted using sym key
    ByteArray sym_key = enclave_data->decrypt_message(enc_sym_key);
    ByteArray dec_state_data = tcf::crypto::skenc::DecryptMessage(
                                   sym_key, enc_state_data);
    uint8_t concat_str_hash[SGX_HASH_SIZE] = {0};

    ComputeSHA256Hash(ByteArrayToString(dec_state_data), concat_str_hash);

    //Concatenate hash, sym enc key, unique id, nonce
    ByteArray concat_ba = StrToByteArray( ByteArrayToStr(ByteArray(std::begin(concat_str_hash),
                                               std::end(concat_str_hash)))
                                + ByteArrayToStr(sym_key)
                                + ByteArrayToStr(unique_id_hex)
                                + ByteArrayToStr(generated_nonce_hex));

    //SHA256 of concatenated byte array is calculated
    ComputeSHA256Hash(ByteArrayToString(concat_ba), concat_str_hash);

    if (enclave_data->verify_signature(
            ByteArray(std::begin(concat_str_hash),
            std::end(concat_str_hash)), output_sig) != 0) {
        this->SetStatus((int)ERR_KME_REPL_SIG_VERIF_FAILED, out_work_order_data);
        ThrowIf<ValueError>(true, "Signature verification failed while setting state.");
    }

    //Delete sym key
    sym_key.clear();

    //Update internal private state. Split string concatenation of pvt_data,
    //enc_key_map, sig_key_map delimited by semicolon (;)
    std::string str = ByteArrayToStr(dec_state_data);
    std::string::size_type pos = str.find_first_of(';');
    std::string pvt_state_data = str.substr(0, pos);

    str = str.substr(pos+1);
    pos = str.find_first_of(';');
    std::string enc_key_map_ser = str.substr(0, pos);

    std::string sig_key_map_ser = str.substr(pos+1);

    sig_key_map = derializeSigKeyMap(sig_key_map_ser);

    wpe_enc_key_map = derializeEncKeyMap(enc_key_map_ser);

    enclave_data->updateEnclaveData(ByteArrayToStr(dec_state_data));

    //Add output
    SetStatus(KME_REPL_OP_SUCCESS, out_work_order_data);
    //@TODO
    //AddOutput(1, unique_id_hex, out_work_order_data); // updated KME attestation data

    uint8_t* out_sealed_enclave_data;
    out_sealed_enclave_data = (uint8_t*) malloc(enclave_data->get_sealed_data_size());
    enclave_data->get_sealed_data(out_sealed_enclave_data);
    ByteArray sealed_ba = ByteArray(out_sealed_enclave_data, out_sealed_enclave_data+(enclave_data->get_sealed_data_size()));
    AddOutput(1, sealed_ba, out_work_order_data); // encrypted sealed data as base64
}

void KMEWorkloadProcessor::GetUniqueId(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    ByteArray signing_key = {};
    ByteArray verification_key_hex = {};
    ByteArray verification_key_signature_hex = {};
    ByteArray nonce_hex = in_work_order_data[0].decrypted_data;

    tcf::error::ThrowIf<tcf::error::WorkloadError>(
        (this->ext_work_order_info_kme == nullptr),
        "ExtWorkOrderInfoKME instance is not initialized");

    int err = ext_work_order_info_kme->GenerateSigningKey(
        ExtWorkOrderInfo::KeyType_SECP256K1, nonce_hex, signing_key,
        verification_key_hex, verification_key_signature_hex);

    if (!err) {
        sig_key_map[verification_key_hex] = signing_key;

        std::string result_str = std::to_string(err);
        // Concatenate status, verification_key and verification_key_signature
        // delimited by " "
        ByteArray out_data_bytes = StrToByteArray( result_str
                                   + " "
                                   + ByteArrayToStr(verification_key_hex)
                                   + " "
                                   + ByteArrayToStr(verification_key_signature_hex));

        AddOutput(0, out_data_bytes, out_work_order_data);
    }
}  // KMEWorkloadProcessor::GetUniqueId

/* 
 *  Register WPE enclave with this instance of KME enclave.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
*/
void KMEWorkloadProcessor::Register(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {
    // If in_work_order_data is empty
    if (in_work_order_data.size() == 0) {
        this->SetStatus((int)ERR_WPE_REG_FAILED,
            out_work_order_data);
        ThrowIf<ValueError>(true, "Registration request is empty");
    }
    /* Registration request is serialized json rpc string
     * with params
      {
       "unique_id": <unique_id>,
       "proof_data": <proof_data>,
       "wpe_encryption_key": <wpe_encryption_key>,
       "mr_enclave": <mr_enclave>
      }
    */
    // Parse the work order request
    ByteArray reg_request = in_work_order_data[0].decrypted_data;
    std::string reg_request_string = ByteArrayToStr(reg_request);
    JsonValue parsed(json_parse_string(reg_request_string.c_str()));
    tcf::error::ThrowIfNull(
        parsed.value,
	"failed to parse the registration request, badly formed JSON");

    JSON_Object* request_object = json_value_get_object(parsed);
    tcf::error::ThrowIfNull(request_object,
	"Missing JSON object in registration request");

    /* Get unique_id from params */
    const char* s_value = nullptr;
    s_value = json_object_dotget_string(request_object, "unique_id");
    if (s_value == nullptr) {
        this->SetStatus((int)ERR_WPE_REG_FAILED,
            out_work_order_data);
        ThrowIf<ValueError>(true,
                        "Extracting unique_id from params failed");
    }
    std::string unique_id(s_value);

    /* Get attestation_data from params */
    s_value = json_object_dotget_string(request_object, "proof_data");
    if (s_value == nullptr) {
        this->SetStatus((int)ERR_WPE_REG_FAILED,
            out_work_order_data);
        ThrowIf<ValueError>(true,
                        "Extracting proof_data from params failed");
    }
    std::string proof_data(s_value);

    /* Get wpe_encryption_key from params */
    s_value = json_object_dotget_string(request_object, "wpe_encryption_key");
    if (s_value == nullptr) {
        this->SetStatus((int)ERR_WPE_REG_FAILED,
            out_work_order_data);
        ThrowIf<ValueError>(true,
                        "Extracting wpe_encryption_key from params failed");
    }
    std::string wpe_encryption_key(s_value);

    /* Get mr_enclave from params */
    s_value = json_object_dotget_string(request_object, "mr_enclave");
    if (s_value == nullptr) {
        this->SetStatus((int)ERR_WPE_REG_FAILED,
            out_work_order_data);
        ThrowIf<ValueError>(true,
                        "Extracting mr_enclave from params failed");
    }
    std::string mr_enclave(s_value);
 
    ByteArray unique_id_bytes = StrToByteArray(unique_id);
    ByteArray e_key = {};
    ByteArray verification_key_hash = {};
    ByteArray mr_enclave_bytes = {};
    ByteArray mr_signer = {};

    tcf::error::ThrowIf<tcf::error::WorkloadError>(
        (this->ext_work_order_info_kme == nullptr),
        "ExtWorkOrderInfoKME instance is not initialized");

    // Not simulator mode
    if (!this->isSgxSimulator()) {
        int err = ext_work_order_info_kme->VerifyAttestationWpe(
	    StrToByteArray(proof_data),
            unique_id_bytes,
            mr_enclave_bytes, mr_signer,
            e_key, verification_key_hash);
        if (err != 0) {
            this->SetStatus(err, out_work_order_data);
            ThrowIf<ValueError>(true, "WPE attestation verification failed");
        }
    }
    auto search = sig_key_map.find(unique_id_bytes);

    if (search != sig_key_map.end()) {

        // If this is simulator mode, mr_enclave_bytes should not be
        // populated yet. Read the mr_enclave received as a parameter
        // in this WPE registration request and populate it.
        if (this->isSgxSimulator())
            mr_enclave_bytes = HexEncodedStringToByteArray(mr_enclave);

        // Compare MRENCLAVE value
        EnclaveData* enclave_data = EnclaveData::getInstance();
        ByteArray ext_data = enclave_data->get_extended_data();
        if (memcmp(ext_data.data(),
		        mr_enclave_bytes.data(), SGX_HASH_SIZE) != 0) {
            this->SetStatus((int)ERR_MRENCLAVE_NOT_MATCH, out_work_order_data);
            ThrowIf<ValueError>(true, "WPE MRENCLAVE value didn't match");
        }

        if (this->isSgxSimulator()) {
            /// Add the WPE to the sig_key_map
            wpe_enc_key_map[StrToByteArray(wpe_encryption_key)] = WPEInfo(
                sig_key_map[unique_id_bytes]);

            /// Remove the entry to avoid replay attack
            sig_key_map.erase(unique_id_bytes);
            this->SetStatus((int)ERR_WPE_REG_SUCCESS,
                out_work_order_data);
            return;
        }

        // Verify the hash of verification key in the report data and
        // unique_id in in_data
        uint8_t unique_id_hash[SGX_HASH_SIZE] = {0};
        ComputeSHA256Hash(unique_id.c_str(), unique_id_hash);
        if (verification_key_hash != ByteArray(std::begin(unique_id_hash),
                                               std::end(unique_id_hash))){

            this->SetStatus((int)ERR_UNIQUE_ID_NOT_MATCH, out_work_order_data);
            ThrowIf<ValueError>(true, "Unique id value didn't match");
        }

        // Compare if SHA256(wpe_encryption_key) matches
        // with WPE report data [0:31]
        uint8_t encryption_key_hash[SGX_HASH_SIZE] = {0};
        ComputeSHA256Hash(wpe_encryption_key.c_str(), encryption_key_hash);
        if (memcmp(e_key.data(), encryption_key_hash,
                SGX_HASH_SIZE) != 0) {
            this->SetStatus((int)ERR_ENCRYPTION_KEY_NOT_MATCH,
                out_work_order_data);
            ThrowIf<ValueError>(true, "Encryption key hash didn't match");
        }
        // TODO: MRSIGNER value check

        /// Add the WPE to the sig_key_map
        wpe_enc_key_map[StrToByteArray(wpe_encryption_key)] = WPEInfo(
            sig_key_map[unique_id_bytes]);

        /// Remove the entry to avoid replay attack
        sig_key_map.erase(unique_id_bytes);
    }
    else {
        this->SetStatus((int)ERR_WPE_KEY_NOT_FOUND, out_work_order_data);
        ThrowIf<ValueError>(true, "WPE verification key not found");
    }
    this->SetStatus((int)ERR_WPE_REG_SUCCESS, out_work_order_data);
}  // KMEWorkloadProcessor::Register


/*
 *  Generate work order key data to be used by WPE for
 *  work order response signing and encryption.
 *
 *  @param in_work_order_data - vector of work order indata
 *  @param out_work_order_data - vector of work order outdata
*/
void KMEWorkloadProcessor::PreprocessWorkorder(
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    tcf::error::ThrowIf<tcf::error::WorkloadError>(
        (this->ext_work_order_info_kme == nullptr),
        "ExtWorkOrderInfoKME instance is not initialized");

    // Get WPE encryption key from in data
    ByteArray wpe_encrypt_key = StrToByteArray(
        ext_work_order_info_kme->GetExtWorkOrderData().c_str());

    auto search_enc_key = wpe_enc_key_map.find(wpe_encrypt_key);
    if (search_enc_key != wpe_enc_key_map.end()) {
        WPEInfo wpe_info = wpe_enc_key_map[wpe_encrypt_key];
        ByteArray wo_key_data = {};

        int status = ext_work_order_info_kme->CreateWorkOrderKeyInfo(
            wpe_encrypt_key, wpe_info.signing_key, wo_key_data);

        if (!status) {
            // skip the key map update if number of allowed work orders
            // for pre-processing is unlimited
            if (max_wo_count_ != KME_WO_COUNT_UNLIMITED) {
                wpe_info.workorder_count++;
                if (wpe_info.workorder_count >= max_wo_count_) {
                    // remove the encryption key from the map because
                    // number of pre-processed work orders reached max limit
                    wpe_enc_key_map.erase(wpe_encrypt_key);
                    SetStatus(ERR_WPE_MAX_WO_COUNT_REACHED,
                        out_work_order_data);
                    return;
                } else {
                    wpe_enc_key_map[wpe_encrypt_key] = wpe_info;
                }
            }
            AddOutput(0, wo_key_data, out_work_order_data);
        } else {
            SetStatus(ERR_WPE_KEY_NOT_FOUND, out_work_order_data);
        }
    }
}  // KMEWorkloadProcessor::PreprocessWorkorder

/*
 *  Add output data after work order processing to out data vector.
 *
 *  @param index - index of the out data in the vector
 *  @param out_work_order_data - vector of work order outdata
*/
void KMEWorkloadProcessor::AddOutput(int index, ByteArray& data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    int out_wo_data_size = out_work_order_data.size();
    // If the out_work_order_data has entry to hold the data
    if (index < out_wo_data_size) {
        tcf::WorkOrderData out_wo_data = out_work_order_data.at(index);
        out_wo_data.decrypted_data = data;
    }
    else {
        // Create a new entry
        out_work_order_data.emplace_back(index, data);
    }
}  // KMEWorkloadProcessor::AddOutput

/*
 *  Set status of workload execution in work order out data.
 *
 *  @param result - Result of workload execution
 *  @param out_work_order_data - vector of work order outdata
*/
void KMEWorkloadProcessor::SetStatus(const int result,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    std::string result_str = std::to_string(result);
    ByteArray ba(result_str.begin(), result_str.end());
    AddOutput(0, ba, out_work_order_data);
}  // KMEWorkloadProcessor::SetStatus

/*
 *  Process work order request based on workload identifier
 *  and package the result in the work order out data.
 *
 *  @param workload_id         Workload identifier string
 *  @param requester_id        Requester ID to identify who submitted
 *                           the work order
 *  @param worker_id           Worker ID, a unique string identifying
 *                           this type of work order processor
 *  @param work_order_id       Unique work order ID for this type of
 *                           work order processor
 *  @param in_work_order_data  Work order data input submitted to the
 *                           work order processor
 *  @param out_work_order_data Work order data returned by the
 *                           work order processor
*/
void KMEWorkloadProcessor::ProcessWorkOrder(
    std::string workload_id,
    const ByteArray& requester_id,
    const ByteArray& worker_id,
    const ByteArray& work_order_id,
    const std::vector<tcf::WorkOrderData>& in_work_order_data,
    std::vector<tcf::WorkOrderData>& out_work_order_data) {

    if (workload_id == "state-uid") {
        GetStateReplicationId(in_work_order_data, out_work_order_data);
    } if (workload_id == "state-request") {
        CreateStateReplicatonRequest(in_work_order_data, out_work_order_data);
    } else if (workload_id == "get-state") {
        GetStateReplica(in_work_order_data, out_work_order_data);
    } else if (workload_id == "set-state") {
        UpdateState(in_work_order_data, out_work_order_data);
    } else if (workload_id == "kme-uid") {
        GetUniqueId(in_work_order_data, out_work_order_data);
    } else if (workload_id == "kme-reg") {
        Register(in_work_order_data, out_work_order_data);
    } else {
        PreprocessWorkorder(
            in_work_order_data, out_work_order_data);
    }
}  // KMEWorkloadProcessor::ProcessWorkOrder

int KMEWorkloadProcessor::isSgxSimulator() {
#if defined(SGX_SIMULATOR)
#if SGX_SIMULATOR == 1
    return 1;
#else  // SGX_SIMULATOR not 1
    return 0;
#endif  //  #if SGX_SIMULATOR == 1
#else  // SGX_SIMULATOR not defined
    return 0;
#endif  // defined(SGX_SIMULATOR)
}

std::string KMEWorkloadProcessor::serializeSigKeyMap(){
    std::string serialized_str;
    std::map<ByteArray, ByteArray>::iterator it;

    for (it = sig_key_map.begin(); it != sig_key_map.end(); it++){
        serialized_str += ByteArrayToStr(it->first);
        serialized_str += ",";
        serialized_str += ByteArrayToStr(it->second);
        serialized_str += " ";
    }
    if (serialized_str.length() > 1)
        serialized_str = serialized_str.substr(0, serialized_str.length()-2);
    return serialized_str;
}
std::map<ByteArray, ByteArray> KMEWorkloadProcessor::derializeSigKeyMap(std::string serialized){
    std::map<ByteArray, ByteArray> _sig_key_map;

    while(serialized.length() != 0){
        std::string::size_type pos = serialized.find_first_of(' ');
        std::string map_entry = serialized.substr(0, pos);

        std::string::size_type pos_entry = serialized.find_first_of(',');
        std::string key = map_entry.substr(0, pos_entry);
        std::string value = map_entry.substr(pos_entry+1);
        _sig_key_map[StrToByteArray(key)] = StrToByteArray(value);

        serialized = serialized.substr(pos+1);
    }

    return _sig_key_map;
}
std::string KMEWorkloadProcessor::serializeEncKeyMap(){
    std::string serialized_str;
    std::map<ByteArray, WPEInfo>::iterator it;

    for (it = wpe_enc_key_map.begin(); it != wpe_enc_key_map.end(); it++){
        serialized_str += ByteArrayToStr(it->first);
        serialized_str += ":";
        serialized_str += ByteArrayToStr((it->second).serialize());
        serialized_str += "|";
    }

    return serialized_str;
}
std::map<ByteArray, WPEInfo> KMEWorkloadProcessor::derializeEncKeyMap(std::string serialized){
    std::map<ByteArray, WPEInfo> _enc_key_map;

    while(serialized.length() != 0){
        std::string::size_type pos = serialized.find_first_of('|');       
        std::string map_entry = serialized.substr(0, pos);

        std::string::size_type pos_entry = map_entry.find_first_of(':');
        std::string key = map_entry.substr(0, pos_entry);
        std::string value = map_entry.substr(pos_entry+1);
        WPEInfo w_info = WPEInfo();        
        w_info.deserialize(StrToByteArray(value));
        _enc_key_map[StrToByteArray(key)] = w_info;
        serialized = serialized.substr(pos+1);
    }

    return _enc_key_map;
}
