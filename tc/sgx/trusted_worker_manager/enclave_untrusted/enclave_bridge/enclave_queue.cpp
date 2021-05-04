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

#include <stdlib.h>
#include <string>
#include <pthread.h>
#include <queue>

#include "error.h"
#include "tcf_error.h"
#include "types.h"

#include "log.h"

#include "enclave_queue.h"


namespace tcf {

    namespace enclave_queue {

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        int EnclaveQueue::pop() {
            pthread_mutex_lock(&mutex);
            while (queue_.empty()) {
                pthread_cond_wait(&cond, &mutex);
            }
            int item = queue_.front();
            queue_.pop();
            pthread_mutex_unlock(&mutex);
            return item;
        }  // EnclaveQueue::pop

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void EnclaveQueue::push(const int& item) {
            pthread_mutex_lock(&mutex);
            queue_.push(item);
            pthread_mutex_unlock(&mutex);
            pthread_cond_signal(&cond);
        }  // EnclaveQueue::push


        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        ReadyEnclave::ReadyEnclave(EnclaveQueue *queue) {
                queue_ = queue;
                enclaveIndex_ = queue_->pop();
        }  // ReadyEnclave::ReadyEnclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        ReadyEnclave::~ReadyEnclave() {
                if (this->queue_) queue_->push(this->enclaveIndex_);
        }  // ReadyEnclave::~ReadyEnclave

    }  // namespace enclave_queue

}  // namespace tcf
