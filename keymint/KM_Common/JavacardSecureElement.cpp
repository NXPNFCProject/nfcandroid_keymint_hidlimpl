/*
 * Copyright 2020, The Android Open Source Project
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
/******************************************************************************
*
*  The original Work has been changed by NXP.
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  Copyright 2024 NXP
*
******************************************************************************/

#define LOG_TAG "javacard.keymint.device.strongbox-impl"
#include "JavacardSecureElement.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <regex.h>
#include <string>
#include <vector>

#ifdef INIT_USING_SEHAL_TRANSPORT
#include <HalToHalTransport.h>
#endif
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <keymaster/android_keymaster_messages.h>

#include "keymint_utils.h"

namespace keymint::javacard {
using ::aidl::android::hardware::security::keymint::ErrorCode;
const std::vector<uint8_t> gStrongBoxAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};

namespace {
keymaster_error_t aidlEnumErrorCode2km(ErrorCode err) {
    return static_cast<keymaster_error_t>(err);
}
}  // namespace

keymaster_error_t JavacardSecureElement::initializeJavacard() {
    Array request;
    request.add(Uint(getOsVersion()));
    request.add(Uint(getOsPatchlevel()));
    request.add(Uint(getVendorPatchlevel()));
    auto [item, err] = sendRequest(Instruction::INS_INIT_STRONGBOX_CMD, request);
    return err;
}

void JavacardSecureElement::setDeleteAllKeysPending() {
    isDeleteAllKeysPending = true;
}
void JavacardSecureElement::setEarlyBootEndedPending() {
    isEarlyBootEndedPending = true;
}
void JavacardSecureElement::sendPendingEvents() {
    if (isCardInitPending) {
        if (KM_ERROR_OK == initializeJavacard()) {
            isCardInitPending = false;
        } else {
            LOG(ERROR) << "Error in sending system properties(OS_VERSION, OS_PATCH, VENDOR_PATCH).";
        }
    }

    if (isDeleteAllKeysPending) {
        auto [_, err] = sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
        if (err == KM_ERROR_OK) {
            isDeleteAllKeysPending = false;
        } else {
            LOG(ERROR) << "Error in sending deleteAllKeys.";
        }
    }
    if (isEarlyBootEndedPending) {
        auto [_, err] = sendRequest(Instruction::INS_EARLY_BOOT_ENDED_CMD);
        if (err == KM_ERROR_OK) {
            isEarlyBootEndedPending = false;
        } else {
            LOG(ERROR) << "Error in sending earlyBootEnded.";
        }
    }
}

keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
                                                              const std::vector<uint8_t>& inputData,
                                                              std::vector<uint8_t>& apduOut) {
    uint8_t p1;
    auto err = getP1(&p1);
    if (KM_ERROR_OK != err) {
        LOG(ERROR) << "Kmversion(" << static_cast<int>(version_) << ") is not supported";
        return err;
    }
    apduOut.push_back(static_cast<uint8_t>(APDU_CLS));  // CLS
    apduOut.push_back(static_cast<uint8_t>(ins));       // INS
    apduOut.push_back(static_cast<uint8_t>(p1));   // P1
    apduOut.push_back(static_cast<uint8_t>(APDU_P2));   // P2

    if (USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData |
        // 2 bytes of Le all set to 00. Case 2: Lc = 0  CLS | INS | P1 | P2 | 3
        // bytes of Le all set to 00. Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        if (inputData.size() > 0) {
            apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
            apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
            // Data
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        }
        // Expected length of output.
        // Accepting complete length of output every time.
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
    } else {
        LOG(ERROR) << "Error in constructApduMessage.";
        return (KM_ERROR_INVALID_INPUT_LENGTH);
    }
    return (KM_ERROR_OK);  // success
}

keymaster_error_t JavacardSecureElement::sendData(const std::shared_ptr<ITransport>& transport,
                                                  Instruction ins,
                                                  const std::vector<uint8_t>& inData,
                                                  std::vector<uint8_t>& response) {
    keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    ret = constructApduMessage(ins, inData, apdu);

    if (ret != KM_ERROR_OK) {
        return ret;
    }

    if (!transport->sendData(apdu, response) && (response.size() < 2)) {
        LOG(ERROR) << "Error in sending C-APDU";
        return (KM_ERROR_SECURE_HW_COMMUNICATION_FAILED);
    }
    // Response size should be greater than 2. Cbor output data followed by two
    // bytes of APDU status.
    if (getApduStatus(response) != APDU_RESP_STATUS_OK) {
        LOG(ERROR) << "ERROR Response apdu status = " << std::uppercase << std::hex
                   << getApduStatus(response);
        return (KM_ERROR_UNKNOWN_ERROR);
    }
    // remove the status bytes
    response.pop_back();
    response.pop_back();
    return (KM_ERROR_OK);  // success
}

keymaster_error_t JavacardSecureElement::sendData(Instruction ins,
                                                  const std::vector<uint8_t>& inData,
                                                  std::vector<uint8_t>& response) {
    return sendData(transport_, ins, inData, response);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
    Instruction ins, const Array& request) {
    return sendRequest(transport_, ins, request.encode());
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
    Instruction ins, const std::vector<uint8_t>& command) {
    return sendRequest(transport_, ins, command);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
    Instruction ins) {
    return sendRequest(transport_, ins, std::vector<uint8_t>());
}
#ifdef INIT_USING_SEHAL_TRANSPORT
bool JavacardSecureElement::initSEHal() {
    if (seHalTransport == nullptr) {
        seHalTransport = std::make_shared<HalToHalTransport>(gStrongBoxAppletAID);
    }
    return seHalTransport->openConnection();
}

bool JavacardSecureElement::closeSEHal() {
    bool ret = true;
    if (seHalTransport != nullptr) {
        ret = seHalTransport->closeConnection();
        if (!ret) {
            LOG(INFO) << "Failed to close SE Hal.";
        }
        seHalTransport = nullptr;
    }
    return ret;
}
#endif
std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequestSeHal(
    Instruction ins, const std::vector<uint8_t>& command) {
    if (seHalTransport != nullptr) {
        return sendRequest(seHalTransport, ins, command);
    } else {
        auto [item, err] = sendRequest(ins, command);
        if (err != KM_ERROR_OK) {
#ifdef INIT_USING_SEHAL_TRANSPORT
            if (err == aidlEnumErrorCode2km(ErrorCode::SECURE_HW_COMMUNICATION_FAILED)) {
                LOG(DEBUG) << "OMAPI is not yet available. Send INS: " << static_cast<int>(ins)
                           << " via SE Hal.";
                if (initSEHal()) {
                    return sendRequest(seHalTransport, ins, command);
                }
                LOG(ERROR) << "Failed to initialize SE HAL";
            }
#endif
        }
        return {std::move(item), std::move(err)};
    }
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequestSeHal(
    Instruction ins) {
    return sendRequestSeHal(ins, std::vector<uint8_t>());
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t> JavacardSecureElement::sendRequest(
    const std::shared_ptr<ITransport>& transport, Instruction ins,
    const std::vector<uint8_t>& command) {
    vector<uint8_t> response;
    auto sendError = sendData(transport, ins, command, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

keymaster_error_t JavacardSecureElement::getP1(uint8_t* p1) {
    switch (version_) {
    case KmVersion::KEYMINT_3:
        *p1 = APDU_KEYMINT_3_P1;
        break;
    case KmVersion::KEYMINT_4:
        *p1 = APDU_KEYMINT_4_P1;
        break;
    default:
        return KM_ERROR_UNIMPLEMENTED;
    }
    return KM_ERROR_OK;
}

#ifdef NXP_EXTNS
void JavacardSecureElement::setOperationState(CryptoOperationState state) {
    transport_->setCryptoOperationState(state);
}
#endif
}  // namespace keymint::javacard
