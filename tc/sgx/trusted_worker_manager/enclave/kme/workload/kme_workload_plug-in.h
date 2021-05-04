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

#pragma once

#include <stdlib.h>
#include <string>

#include "types.h"
#include "workload_processor_kme.h"

#define KME_WO_COUNT_UNLIMITED   0
#define KME_MAX_WO_COUNT          KME_WO_COUNT_UNLIMITED

// contains registered WPE info
typedef struct WPEInfo {
    // number of preprocessed workorders for this WPE
    uint64_t workorder_count;
    // private signing key associated with this WPE
    ByteArray signing_key;

    WPEInfo();
    WPEInfo(const ByteArray& _sk);
    WPEInfo(const uint64_t _wo_c, const ByteArray& _sk);

    /*
    *  Serialize WPEInfo into a ByteArray, the member variables
    *  delimited by a comma (,).
    *
    *  @returns Serialized WPEInfo as bytearray
    *
    */
    ByteArray serialize(){
        std::string serialized = std::to_string(workorder_count);
        serialized += ",";
        serialized += ByteArrayToStr(signing_key);

        return StrToByteArray(serialized);
    }

    /*
    *  Deserialize ByteArray to WPEInfo instance.
    *
    *  @param ba - Serialized WPEInfo instance as a ByteArray
    *
    */
    void deserialize(ByteArray ba){
        std::string str = ByteArrayToStr(ba);

        std::string::size_type pos = str.find_first_of(',');

        std::string count = str.substr(0, pos);
        workorder_count = std::stoul(count.c_str());

        std::string key = str.substr(pos+1);
        signing_key = StrToByteArray(key);
    }
} WPEInfo;

class KMEWorkloadProcessor: public WorkloadProcessorKME {

public:

    KMEWorkloadProcessor(uint64_t max_wo_count = KME_MAX_WO_COUNT) {
       max_wo_count_ = max_wo_count;
    }

    virtual ~KMEWorkloadProcessor(void) {}

    IMPL_WORKLOAD_PROCESSOR_CLONE(KMEWorkloadProcessor);

    void GetStateReplicationId(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void CreateStateReplicatonRequest(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void GetStateReplica(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void UpdateState(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void GetUniqueId(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void Register(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void PreprocessWorkorder(
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    void ProcessWorkOrder(
        std::string workload_id,
        const ByteArray& requester_id,
        const ByteArray& worker_id,
        const ByteArray& work_order_id,
        const std::vector<tcf::WorkOrderData>& in_work_order_data,
        std::vector<tcf::WorkOrderData>& out_work_order_data) override;
    std::string serializeSigKeyMap();
    std::map<ByteArray, ByteArray> derializeSigKeyMap(std::string serialized);
    std::string serializeEncKeyMap();
    std::map<ByteArray, WPEInfo> derializeEncKeyMap(std::string serialized);

private:
    int isSgxSimulator();

    static void AddOutput(int index, ByteArray& data,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    static void SetStatus(const int result,
        std::vector<tcf::WorkOrderData>& out_work_order_data);

    /* Need static maps since we need to persist the maps across the
     * multiple KME workload processor instances for different workload ids.
     */
    static std::map<ByteArray, ByteArray> sig_key_map;
    static std::map<ByteArray, WPEInfo> wpe_enc_key_map;

    uint64_t max_wo_count_;
};  // KMEWorkloadProcessor
