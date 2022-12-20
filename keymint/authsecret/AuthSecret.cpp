/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
 ** Copyright 2022 NXP
 **
 *********************************************************************************/

#include "AuthSecret.h"
#include "EseTransportUtils.h"
#include "OmapiTransport.h"
#include <android-base/logging.h>

#define APDU_CLS 0x80
#define APDU_P1 0x00
#define APDU_P2 0x00

enum class Instruction {
  INS_VERIFY_PIN = 0x20,
  INS_CLEAR_APPROVED_STATUS = 0x30,
};

using keymint::javacard::OmapiTransport;

const std::vector<uint8_t> gAuthSecretAppletAID = {0xA0, 0x00, 0x00, 0x03, 0x96,
                                                   0x54, 0x53, 0x00, 0x00, 0x00,
                                                   0x01, 0x00, 0x52};
static OmapiTransport *gTransport = new OmapiTransport(gAuthSecretAppletAID);

namespace aidl {
namespace android {
namespace hardware {
namespace authsecret {

static bool constructApdu(Instruction ins, const std::vector<uint8_t> &input,
                          std::vector<uint8_t> &out,
                          std::vector<uint8_t> timeout) {
  const std::vector<uint8_t> tagVerifyPin = {0x81, 0x50};

  /* For future purpose*/
  const std::vector<uint8_t> tagVerifyPinWithTimeout = {0x82, 0x50};
  const std::vector<uint8_t> tagTimeout = {0x42};

  /* Insert CLA, INS, P1, P2*/
  out.push_back(static_cast<uint8_t>(APDU_CLS));
  out.push_back(static_cast<uint8_t>(ins));
  out.push_back(static_cast<uint8_t>(APDU_P1));
  out.push_back(static_cast<uint8_t>(APDU_P2));

  switch (ins) {
  case Instruction::INS_VERIFY_PIN:
    if (timeout.size()) {
      /* Insert Length*/
      uint8_t apduLength = (tagVerifyPinWithTimeout.size() + input.size() +
                            tagTimeout.size() + timeout.size());
      out.push_back(static_cast<uint8_t>(apduLength));

      /*Insert Payload*/
      out.insert(out.end(), tagVerifyPinWithTimeout.begin(),
                 tagVerifyPinWithTimeout.end());
      out.insert(out.end(), input.begin(), input.end());
      out.insert(out.end(), tagTimeout.begin(), tagTimeout.end());
      out.insert(out.end(), timeout.begin(), timeout.end());
    } else {
      /* Insert Length*/
      uint8_t apduLength = (tagVerifyPin.size() + input.size());
      out.push_back(static_cast<uint8_t>(apduLength));

      /*Insert Payload*/
      out.insert(out.end(), tagVerifyPin.begin(), tagVerifyPin.end());
      out.insert(out.end(), input.begin(), input.end());
    }
    break;
  case Instruction::INS_CLEAR_APPROVED_STATUS:
    /* Nothing to do. No Payload for Clear approved status*/
    break;
  default:
    LOG(ERROR) << "Unknown INS. constructApdu failed";
    return false;
  }

  /* Insert LE */
  out.push_back(static_cast<uint8_t>(0x00));
  return true;
}

// Methods from ::android::hardware::authsecret::IAuthSecret follow.
::ndk::ScopedAStatus
AuthSecret::setPrimaryUserCredential(const std::vector<uint8_t> &in_secret) {
  LOG(INFO) << "setPrimaryUserCredential: Enter";
  std::vector<uint8_t> cmd;
  std::vector<uint8_t> timeout;
  bool status =
      constructApdu(Instruction::INS_VERIFY_PIN, in_secret, cmd, timeout);
  if (!status) {
    LOG(ERROR) << "constructApdu failed";
    return ::ndk::ScopedAStatus::ok();
  }

  std::vector<uint8_t> resp;
  if (!gTransport->sendData(cmd, resp)) {
    LOG(ERROR) << "Error in sending data in sendData.";
  }
  LOG(INFO) << "setPrimaryUserCredential: Exit";

  return ::ndk::ScopedAStatus::ok();
}

} // namespace authsecret
} // namespace hardware
} // namespace android
} // aidl
