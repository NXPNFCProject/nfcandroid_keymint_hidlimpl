/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
/******************************************************************************
 **
 ** The original Work has been changed by NXP.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 ** http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 **
 ** Copyright 2020-2021, 2023-2026 NXP
 **
 *********************************************************************************/
#define LOG_TAG "HalToHalTransport"

#include <vector>
#include <signal.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <iomanip>

#include <HalToHalTransport.h>
#include <EseTransportUtils.h>
#include <IntervalTimer.h>

namespace keymint::javacard {
void SessionTimerFunc(union sigval arg){
     LOG(INFO) << "Session Timer expired !!";
     HalToHalTransport *obj = (HalToHalTransport*)arg.sival_ptr;
     if(obj != nullptr)
       obj->closeConnection();
}
bool HalToHalTransport::openConnection() {
	  return mAppletConnection.connectToSEService();
}

bool HalToHalTransport::sendData(const vector<uint8_t>& inData, vector<uint8_t>& output) {
    std::vector<uint8_t> cApdu(inData);
#ifdef INTERVAL_TIMER
    LOG(DEBUG) << "stop the timer";
    mSessionIdleTimer.kill();
#endif
     if (!isConnected()) {
         if (!openConnection()) {
             return false;
         }
     }
     std::vector<uint8_t> selectResponse;
     bool status = mAppletConnection.openChannelToApplet(selectResponse);
     if (!status) {
         LOG(ERROR) << " Failed to open Logical Channel ,response " << selectResponse;
         output = std::move(selectResponse);
     } else {
         status = mAppletConnection.transmit(cApdu, output);
         if (output.size() < 2 ||
             (output.size() >= 2 &&
              (output.at(output.size() - 2) == LOGICAL_CH_NOT_SUPPORTED_SW1 &&
               output.at(output.size() - 1) == LOGICAL_CH_NOT_SUPPORTED_SW2))) {
             LOG(ERROR) << "transmit failed ,close the channel";
             closeConnection();
             return false;
         }
     }
#ifdef INTERVAL_TIMER
     kickSessionIdleTimer();
#endif
     return status;
}

bool HalToHalTransport::closeConnection() {
    return mAppletConnection.close();
}

bool HalToHalTransport::isConnected() {
    return mAppletConnection.isServiceConnected();
}

bool HalToHalTransport::setAppletAid(const std::vector<uint8_t>& aid) {
    return mAppletConnection.setAppletAid(aid);
}

void HalToHalTransport::setCryptoOperationState(uint8_t state) {
    mSBAccessController.setCryptoOperationState(state);
    kickSessionIdleTimer();
}

void HalToHalTransport::kickSessionIdleTimer() {

    std::chrono::milliseconds actual_duration =
        mSessionTimeout.value_or(mAppletConnection.getSessionTimeout());

    if (actual_duration <= std::chrono::milliseconds::zero()) {
        LOG(INFO) << "Timeout is " << actual_duration.count()
                  << " ms. Instantly closing connection.";
        closeConnection();
        return;
    }

    LOG(INFO) << "Set the timer with timeout " << actual_duration.count() << " ms";

    if (!mSessionIdleTimer.set(actual_duration, this, SessionTimerFunc)) {
        LOG(ERROR) << "Failed to arm session timer. Closing connection.";
        closeConnection();
    }
}

void HalToHalTransport::configureSessionTimeout(std::optional<std::chrono::milliseconds> duration) {
    mSessionTimeout = duration;
}

} // namespace keymint::javacard
