/*
 * Copyright (C) 2020 The Android Open Source Project
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
 ** Copyright 2022,2025 NXP
 **
 *********************************************************************************/
#define LOG_TAG "authsecret.nxp-service"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "AuthSecret.h"

using ::aidl::android::hardware::authsecret::AuthSecret;

#define NXP_EN_SN110U 1
#define NXP_EN_SN100U 1
#define NXP_EN_SN220U 1
#define NXP_EN_PN557 1
#define NXP_EN_PN560 1
#define NXP_EN_SN300U 1
#define NXP_EN_SN330U 1
#define NFC_NXP_MW_ANDROID_VER (16U)  /* Android version used by NFC MW */
#define NFC_NXP_MW_VERSION_MAJ (0x05) /* MW Major Version */
#define NFC_NXP_MW_VERSION_MIN (0x00) /* MW Minor Version */
#define NFC_NXP_MW_CUSTOMER_ID (0x00) /* MW Customer Id */
#define NFC_NXP_MW_RC_VERSION (0x00)  /* MW RC Version */

/******************************************************************************
 * Function         printIARVersion
 *
 * Description      This function is called to print the IAR version
 *
 * Returns          None
 *
 ******************************************************************************/
static void printIARVersion() {
    uint32_t validation = (NXP_EN_SN100U << 13);
    validation |= (NXP_EN_SN110U << 14);
    validation |= (NXP_EN_SN220U << 15);
    validation |= (NXP_EN_PN560 << 16);
    validation |= (NXP_EN_SN300U << 17);
    validation |= (NXP_EN_SN330U << 18);
    validation |= (NXP_EN_PN557 << 11);

    char version[60];  // Buffer to store formatted string
    sprintf(version, "IAR Version: NFC_AR_%02X_%05X_%02d.%02X.%02X",
            NFC_NXP_MW_CUSTOMER_ID, validation, NFC_NXP_MW_ANDROID_VER,
            NFC_NXP_MW_VERSION_MAJ, NFC_NXP_MW_VERSION_MIN);
    LOG(INFO) << version;
}

int main() {
	printIARVersion();
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    std::shared_ptr<AuthSecret> authsecret = ndk::SharedRefBase::make<AuthSecret>();

    const std::string instance = std::string() + AuthSecret::descriptor + "/default";
    LOG(INFO) << "adding authsecret service instance: " << instance;
    binder_status_t status = AServiceManager_addService(
        authsecret->asBinder().get(), instance.c_str());
    CHECK_EQ(status, STATUS_OK);

    ABinderProcess_joinThreadPool();
    return -1; // Should never be reached
}
