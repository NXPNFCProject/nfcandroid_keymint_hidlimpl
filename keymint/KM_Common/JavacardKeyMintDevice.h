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
 *  Copyright 2022-2024 NXP
 *
 ******************************************************************************/
#pragma once

#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
#include <android/binder_auto_utils.h>

#include "CborConverter.h"
#include "JavacardSecureElement.h"

namespace keymint::javacard {
using aidl::android::hardware::security::keymint::AttestationKey;
using aidl::android::hardware::security::keymint::BeginResult;
using aidl::android::hardware::security::keymint::Certificate;
using aidl::android::hardware::security::keymint::HardwareAuthToken;
using aidl::android::hardware::security::keymint::KeyCharacteristics;
using aidl::android::hardware::security::keymint::KeyCreationResult;
using aidl::android::hardware::security::keymint::KeyFormat;
using aidl::android::hardware::security::keymint::KeyMintHardwareInfo;
using aidl::android::hardware::security::keymint::KeyParameter;
using aidl::android::hardware::security::keymint::KeyPurpose;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::secureclock::TimeStampToken;
using aidl::android::hardware::security::sharedsecret::SharedSecretParameters;
using cppbor::Item;
using ::keymint::javacard::CborConverter;
using ::keymint::javacard::JavacardSecureElement;
using ndk::ScopedAStatus;
using std::array;
using std::optional;
using std::shared_ptr;
using std::vector;

struct SEKeyMintBeginResult {
    int64_t challenge;
    std::vector<KeyParameter> params;
    int32_t bufMode;
    int64_t opHandle;
    int32_t macLength;
};

class JavacardKeyMintDevice {
  public:
    explicit JavacardKeyMintDevice(shared_ptr<JavacardSecureElement> card)
        : securitylevel_(SecurityLevel::STRONGBOX), card_(std::move(card)) {}
    virtual ~JavacardKeyMintDevice() {}

    // Methods from ::ndk::ICInterface follow.
    binder_status_t dump(int fd, const char** args, uint32_t num_args);

    ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info);

    ScopedAStatus addRngEntropy(const vector<uint8_t>& data);

    ScopedAStatus generateKey(const vector<KeyParameter>& keyParams,
                              const optional<AttestationKey>& attestationKey,
                              KeyCreationResult* creationResult);

    ScopedAStatus importKey(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                            const vector<uint8_t>& keyData,
                            const optional<AttestationKey>& attestationKey,
                            KeyCreationResult* creationResult);

    ScopedAStatus importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                   const vector<uint8_t>& wrappingKeyBlob,
                                   const vector<uint8_t>& maskingKey,
                                   const vector<KeyParameter>& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   KeyCreationResult* creationResult);

    ScopedAStatus upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                             const vector<KeyParameter>& upgradeParams,
                             vector<uint8_t>* keyBlob);

    ScopedAStatus deleteKey(const vector<uint8_t>& keyBlob);
    ScopedAStatus deleteAllKeys();
    ScopedAStatus destroyAttestationIds();

    virtual ScopedAStatus begin(KeyPurpose in_purpose, const std::vector<uint8_t>& in_keyBlob,
                                const std::vector<KeyParameter>& in_params,
                                const std::optional<HardwareAuthToken>& in_authToken,
                                SEKeyMintBeginResult* beginResult);

    ScopedAStatus deviceLocked(bool passwordOnly,
                               const optional<TimeStampToken>& timestampToken);

    ScopedAStatus earlyBootEnded();

    ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& in_keyBlob,
                                        const std::vector<uint8_t>& in_appId,
                                        const std::vector<uint8_t>& in_appData,
                                        std::vector<KeyCharacteristics>* _aidl_return);

    ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& storageKeyBlob,
                                               std::vector<uint8_t>* ephemeralKeyBlob);

    ScopedAStatus getRootOfTrustChallenge(array<uint8_t, 16>* challenge);

    ScopedAStatus getRootOfTrust(const array<uint8_t, 16>& challenge,
                                 vector<uint8_t>* rootOfTrust);

    ScopedAStatus sendRootOfTrust(const vector<uint8_t>& rootOfTrust);

    ScopedAStatus setAdditionalAttestationInfo(const vector<KeyParameter>& keyParams);

  private:
    keymaster_error_t parseWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                      std::vector<uint8_t>& iv, std::vector<uint8_t>& transitKey,
                                      std::vector<uint8_t>& secureKey, std::vector<uint8_t>& tag,
                                      vector<KeyParameter>& authList, KeyFormat& keyFormat,
                                      std::vector<uint8_t>& wrappedKeyDescription);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendBeginImportWrappedKeyCmd(
        const std::vector<uint8_t>& transitKey, const std::vector<uint8_t>& wrappingKeyBlob,
        const std::vector<uint8_t>& maskingKey, const vector<KeyParameter>& unwrappingParams);

    std::tuple<std::unique_ptr<Item>, keymaster_error_t>
    sendFinishImportWrappedKeyCmd(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                                  const std::vector<uint8_t>& secureKey,
                                  const std::vector<uint8_t>& tag, const std::vector<uint8_t>& iv,
                                  const std::vector<uint8_t>& wrappedKeyDescription,
                                  int64_t passwordSid, int64_t biometricSid);

    ScopedAStatus defaultHwInfo(KeyMintHardwareInfo* info);

    const SecurityLevel securitylevel_;
    const shared_ptr<JavacardSecureElement> card_;
    CborConverter cbor_;
};

}  // namespace keymint::javacard
