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
*  Copyright 2022-2025 NXP
*
******************************************************************************/
#pragma once
#include <keymaster/km_version.h>
#include <ITransport.h>
#include "CborConverter.h"

#define APDU_CLS 0x80
//#define APDU_P1 0x50
#define APDU_KEYMINT_3_P1 0x60
#define APDU_KEYMINT_4_P1 0x70
#define APDU_P2 0x00
#define APDU_RESP_STATUS_OK 0x9000

#define KEYMINT_CMD_APDU_START 0x20

#define KEYMINT_VENDOR_CMD_APDU_START 0xD0

namespace keymint::javacard {
using keymaster::KmVersion;
using std::shared_ptr;
using std::vector;

enum class Instruction {
    // Keymaster commands
    INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1,
    INS_IMPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 2,
    INS_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 3,
    INS_EXPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 4,
    INS_ATTEST_KEY_CMD = KEYMINT_CMD_APDU_START + 5,
    INS_UPGRADE_KEY_CMD = KEYMINT_CMD_APDU_START + 6,
    INS_DELETE_KEY_CMD = KEYMINT_CMD_APDU_START + 7,
    INS_DELETE_ALL_KEYS_CMD = KEYMINT_CMD_APDU_START + 8,
    INS_ADD_RNG_ENTROPY_CMD = KEYMINT_CMD_APDU_START + 9,
    INS_COMPUTE_SHARED_SECRET_CMD = KEYMINT_CMD_APDU_START + 10,
    INS_DESTROY_ATT_IDS_CMD = KEYMINT_CMD_APDU_START + 11,
    INS_VERIFY_AUTHORIZATION_CMD = KEYMINT_CMD_APDU_START + 12,
    INS_GET_SHARED_SECRET_PARAM_CMD = KEYMINT_CMD_APDU_START + 13,
    INS_GET_KEY_CHARACTERISTICS_CMD = KEYMINT_CMD_APDU_START + 14,
    INS_GET_HW_INFO_CMD = KEYMINT_CMD_APDU_START + 15,
    INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16,
    INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17,
    INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18,
    INS_ABORT_OPERATION_CMD = KEYMINT_CMD_APDU_START + 19,
    INS_DEVICE_LOCKED_CMD = KEYMINT_CMD_APDU_START + 20,
    INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21,
    INS_GET_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 22,
    INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23,
    INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24,
    INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25,
    // INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26,
    INS_INIT_STRONGBOX_CMD = KEYMINT_VENDOR_CMD_APDU_START + 9,
    // RKP Commands
    INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27,
    INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28,
    INS_BEGIN_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 29,
    INS_UPDATE_KEY_CMD = KEYMINT_CMD_APDU_START + 30,
    INS_UPDATE_EEK_CHAIN_CMD = KEYMINT_CMD_APDU_START + 31,
    INS_UPDATE_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 32,
    INS_FINISH_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 33,
    INS_GET_RESPONSE_CMD = KEYMINT_CMD_APDU_START + 34,
    INS_GET_UDS_CERTS_CMD = KEYMINT_CMD_APDU_START + 35,
    INS_GET_DICE_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 36,
    // SE ROT Commands
    INS_GET_ROT_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 45,
    INS_GET_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 46,
    INS_SEND_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 47,
    // MODULE HASH
    INS_SET_ADDITIONAL_ATTESTATION_INFO = KEYMINT_CMD_APDU_START + 49,
};
#ifdef NXP_EXTNS
enum CryptoOperationState { STARTED = 0, FINISHED };
#endif

class JavacardSecureElement {
  public:
    explicit JavacardSecureElement(KmVersion version, shared_ptr<ITransport> transport)
        : version_(version), transport_(std::move(transport)),
          isEarlyBootEndedPending(false),
          isDeleteAllKeysPending(false),
          isCardInitPending(true) {
        transport_->openConnection();
    }
    virtual ~JavacardSecureElement() { transport_->closeConnection(); }

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
                                                                     const Array& request);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(
        Instruction ins, const std::vector<uint8_t>& command);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequestSeHal(
        Instruction ins, const std::vector<uint8_t>& command);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequestSeHal(Instruction ins);

    bool closeSEHal();

    keymaster_error_t sendData(Instruction ins, const std::vector<uint8_t>& inData,
                               std::vector<uint8_t>& response);
    keymaster_error_t constructApduMessage(Instruction& ins, const std::vector<uint8_t>& inputData,
                                           std::vector<uint8_t>& apduOut);
    keymaster_error_t initializeJavacard();
    void sendPendingEvents();
    void setEarlyBootEndedPending();
    void setDeleteAllKeysPending();
#ifdef NXP_EXTNS
    void setOperationState(CryptoOperationState state);
    void cacheModuleHash(const vector<KeyParameter>& keyParams);
#endif
    inline uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
        // Last two bytes are the status SW0SW1
        uint8_t SW0 = inputData.at(inputData.size() - 2);
        uint8_t SW1 = inputData.at(inputData.size() - 1);
        return (SW0 << 8 | SW1);
    }

  private:
    bool initSEHal();
    keymaster_error_t sendData(const std::shared_ptr<ITransport>& transport, Instruction ins,
                               const std::vector<uint8_t>& inData, std::vector<uint8_t>& response);
    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(
        const std::shared_ptr<ITransport>& transport, Instruction ins,
        const std::vector<uint8_t>& command);
    keymaster_error_t getP1(uint8_t* p1);

#ifdef NXP_EXTNS
    vector<KeyParameter> moduleHash;
#endif
    KmVersion version_;
    shared_ptr<ITransport> transport_;
    shared_ptr<ITransport> seHalTransport;
    bool isEarlyBootEndedPending;
    bool isDeleteAllKeysPending;
    bool isCardInitPending;
    CborConverter cbor_;
};
}  // namespace keymint::javacard
