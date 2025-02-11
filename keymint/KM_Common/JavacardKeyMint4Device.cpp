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
 *  Copyright 2025 NXP
 *
 ******************************************************************************/
#define LOG_TAG "javacard.keymint.device.strongbox-impl"

#include "JavacardKeyMint4Device.h"

#include <regex.h>

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <KeyMintUtils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <hardware/hw_auth_token.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/wrapped_key.h>

#include "JavacardKeyMintOperation.h"
#include "JavacardSharedSecret.h"

namespace aidl::android::hardware::security::keymint {
using cppbor::Bstr;
using cppbor::EncodedItem;
using cppbor::Uint;
using ::keymaster::AuthorizationSet;
using ::keymaster::dup_buffer;
using ::keymaster::KeymasterBlob;
using ::keymaster::KeymasterKeyBlob;
using ::keymint::javacard::Instruction;
using std::string;

const std::vector<Tag> kAllowedAdditionalAttestationTags = {
    Tag::MODULE_HASH,
};

ScopedAStatus JavacardKeyMint4Device::getHardwareInfo(KeyMintHardwareInfo* info) {
    return device_->getHardwareInfo(info);
}

ScopedAStatus JavacardKeyMint4Device::generateKey(const vector<KeyParameter>& keyParams,
                                                  const optional<AttestationKey>& attestationKey,
                                                  KeyCreationResult* creationResult) {
    return device_->generateKey(keyParams, attestationKey, creationResult);
}

ScopedAStatus JavacardKeyMint4Device::addRngEntropy(const vector<uint8_t>& data) {
    return device_->addRngEntropy(data);
}

ScopedAStatus JavacardKeyMint4Device::importKey(const vector<KeyParameter>& keyParams,
                                                KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                                const optional<AttestationKey>& attestationKey,
                                                KeyCreationResult* creationResult) {

    return device_->importKey(keyParams, keyFormat, keyData, attestationKey, creationResult);
}

// import wrapped key is divided into 2 stage operation.
ScopedAStatus JavacardKeyMint4Device::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                       const vector<uint8_t>& wrappingKeyBlob,
                                                       const vector<uint8_t>& maskingKey,
                                                       const vector<KeyParameter>& unwrappingParams,
                                                       int64_t passwordSid, int64_t biometricSid,
                                                       KeyCreationResult* creationResult) {
    return device_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey, unwrappingParams,
                                     passwordSid, biometricSid, creationResult);
}

ScopedAStatus JavacardKeyMint4Device::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                 const vector<KeyParameter>& upgradeParams,
                                                 vector<uint8_t>* keyBlob) {
    return device_->upgradeKey(keyBlobToUpgrade, upgradeParams, keyBlob);
}

ScopedAStatus JavacardKeyMint4Device::deleteKey(const vector<uint8_t>& keyBlob) {
    return device_->deleteKey(keyBlob);
}

ScopedAStatus JavacardKeyMint4Device::deleteAllKeys() {
    return device_->deleteAllKeys();
}

ScopedAStatus JavacardKeyMint4Device::destroyAttestationIds() {
    return device_->destroyAttestationIds();
}

ScopedAStatus JavacardKeyMint4Device::begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                                            const std::vector<KeyParameter>& params,
                                            const std::optional<HardwareAuthToken>& authToken,
                                            BeginResult* result) {
    ::keymint::javacard::SEKeyMintBeginResult response;
    auto ret = device_->begin(purpose, keyBlob, params, authToken, &response);
    if (ret.isOk()) {
        result->params = std::move(response.params);
        result->challenge = response.challenge;
        result->operation = ndk::SharedRefBase::make<JavacardKeyMintOperation>(
            static_cast<keymaster_operation_handle_t>(response.opHandle),
            static_cast<BufferingMode>(response.bufMode), response.macLength, card_);
    }
    return ret;
}

ScopedAStatus
JavacardKeyMint4Device::deviceLocked(bool passwordOnly,
                                     const std::optional<TimeStampToken>& timestampToken) {
    return device_->deviceLocked(passwordOnly, timestampToken);
}

ScopedAStatus JavacardKeyMint4Device::earlyBootEnded() {
    return device_->earlyBootEnded();
}

ScopedAStatus JavacardKeyMint4Device::getKeyCharacteristics(
    const std::vector<uint8_t>& keyBlob, const std::vector<uint8_t>& appId,
    const std::vector<uint8_t>& appData, std::vector<KeyCharacteristics>* result) {
    return device_->getKeyCharacteristics(keyBlob, appId, appData, result);
}

ScopedAStatus JavacardKeyMint4Device::convertStorageKeyToEphemeral(
    const std::vector<uint8_t>& /* storageKeyBlob */,
    std::vector<uint8_t>* /* ephemeralKeyBlob */) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus JavacardKeyMint4Device::getRootOfTrustChallenge(array<uint8_t, 16>* challenge) {
    return device_->getRootOfTrustChallenge(challenge);
}

ScopedAStatus JavacardKeyMint4Device::getRootOfTrust(const array<uint8_t, 16>& /*challenge*/,
                                                     vector<uint8_t>* /*rootOfTrust*/) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus JavacardKeyMint4Device::sendRootOfTrust(const vector<uint8_t>& rootOfTrust) {
    return device_->sendRootOfTrust(rootOfTrust);
}

ScopedAStatus
JavacardKeyMint4Device::setAdditionalAttestationInfo(const vector<KeyParameter>& keyParams) {
    // Remove non additional attestation tags
    std::vector<KeyParameter> filtered;
    std::remove_copy_if(keyParams.begin(), keyParams.end(), std::back_inserter(filtered),
                        [](const auto& entry) -> bool {
                            return std::find(kAllowedAdditionalAttestationTags.begin(),
                                             kAllowedAdditionalAttestationTags.end(),
                                             entry.tag) == kAllowedAdditionalAttestationTags.end();
                        });
    return device_->setAdditionalAttestationInfo(filtered);
}

binder_status_t JavacardKeyMint4Device::dump(int fd, const char** args, uint32_t num_args) {
    return device_->dump(fd, args, num_args);
}
}  // namespace aidl::android::hardware::security::keymint
