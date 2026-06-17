# extracted from ac2
import logging
import uuid
from typing import Optional

from ipsw_parser.build_identity import BuildIdentity

logger = logging.getLogger(__name__)

SUPPORTED_DATA_TYPES = {
    "BasebandBootData": False,
    "BasebandData": False,
    "BasebandStackData": False,
    "BasebandUpdaterOutputData": False,
    "BootabilityBundle": False,
    "BuildIdentityDict": False,
    "BuildIdentityDictV2": False,
    "DataType": False,
    "DiagData": False,
    "EANData": False,
    "FDRMemoryCommit": False,
    "FDRTrustData": False,
    "FUDData": False,
    "FileData": False,
    "FileDataDone": False,
    "FirmwareUpdaterData": False,
    "GrapeFWData": False,
    "HPMFWData": False,
    "HostSystemTime": True,
    "KernelCache": False,
    "NORData": False,
    "NitrogenFWData": True,
    "OpalFWData": False,
    "OverlayRootDataCount": False,
    "OverlayRootDataForKey": True,
    "PeppyFWData": True,
    "PersonalizedBootObjectV3": False,
    "PersonalizedData": True,
    "ProvisioningData": False,
    "RamdiskFWData": True,
    "RecoveryOSASRImage": True,
    "RecoveryOSAppleLogo": True,
    "RecoveryOSDeviceTree": True,
    "RecoveryOSFileAssetImage": True,
    "RecoveryOSIBEC": True,
    "RecoveryOSIBootFWFilesImages": True,
    "RecoveryOSImage": True,
    "RecoveryOSKernelCache": True,
    "RecoveryOSLocalPolicy": True,
    "RecoveryOSOverlayRootDataCount": False,
    "RecoveryOSRootTicketData": True,
    "RecoveryOSStaticTrustCache": True,
    "RecoveryOSVersionData": True,
    "RootData": False,
    "RootTicket": False,
    "S3EOverride": False,
    "SourceBootObjectV3": False,
    "SourceBootObjectV4": False,
    "SsoServiceTicket": False,
    "StockholmPostflight": False,
    "SystemImageCanonicalMetadata": False,
    "SystemImageData": False,
    "SystemImageRootHash": False,
    "USBCFWData": False,
    "USBCOverride": False,
    "FirmwareUpdaterPreflight": True,
    "ReceiptManifest": True,
    "FirmwareUpdaterDataV2": False,
    "RestoreLocalPolicy": True,
    "AuthInstallCACert": True,
    "OverlayRootDataForKeyIndex": True,
    # Added in iOS 18.0 beta1
    "FirmwareUpdaterDataV3": True,
    "MessageUseStreamedImageFile": True,
    "UpdateVolumeOverlayRootDataCount": True,
    "URLAsset": True,
}

# extracted from ac2
SUPPORTED_MESSAGE_TYPES = {
    "BBUpdateStatusMsg": False,
    "CheckpointMsg": True,
    "CrashLog": True,
    "DataRequestMsg": False,
    "FDRSubmit": True,
    "MsgType": False,
    "PreviousRestoreLogMsg": False,
    "ProgressMsg": False,
    "ProvisioningAck": False,
    "ProvisioningInfo": False,
    "ProvisioningStatusMsg": False,
    "ReceivedFinalStatusMsg": False,
    "RestoredCrash": True,
    "StatusMsg": False,
    # Added in iOS 18.0 beta1
    "AsyncDataRequestMsg": True,
    "AsyncWait": True,
    "RestoreAttestation": True,
}


RESTORE_MESSAGE_CATALOG = {
    "USBLog": {
        "family": "diagnostic_log",
        "purpose": "Restore-side USB log payload",
    },
    "ProgressMsg": {
        "family": "progress",
        "purpose": "Restore progress update",
    },
    "StatusMsg": {
        "family": "status",
        "purpose": "Restore status and final error reporting",
    },
    "DataRequestMsg": {
        "family": "data_request",
        "purpose": "Synchronous data request from restored",
    },
    "AsyncDataRequestMsg": {
        "family": "data_request",
        "purpose": "Asynchronous data request from restored",
    },
    "PreviousRestoreLogMsg": {
        "family": "historical_log",
        "purpose": "Previous restore log payload",
    },
    "BBUpdateStatusMsg": {
        "family": "baseband",
        "purpose": "Baseband update status",
    },
    "ProvisioningStatusMsg": {
        "family": "provisioning",
        "purpose": "Provisioning status update",
    },
    "ProvisioningAck": {
        "family": "provisioning",
        "purpose": "Provisioning acknowledgement",
    },
    "FDRSubmit": {
        "family": "fdr",
        "purpose": "FDR payload submission",
    },
    "ReceivedFinalStatusMsg": {
        "family": "final_status",
        "purpose": "Restore completion acknowledgement",
    },
    "RestoredCrash": {
        "family": "crash",
        "purpose": "Restored crash report",
    },
    "Checkpoint": {
        "family": "checkpoint",
        "purpose": "Restore checkpoint marker",
    },
    "CheckpointMsg": {
        "family": "checkpoint",
        "purpose": "Restore checkpoint marker",
    },
}

RESTORE_MESSAGE_STATE_KEYS = {
    "restoreOutcome": {
        "family": "restore_state",
        "purpose": "Overall restore outcome reported by restored_update.",
    },
    "restoreChildFailures": {
        "family": "restore_state",
        "purpose": "Child-operation failures accumulated during restore.",
    },
    "restoreAnomalies": {
        "family": "restore_state",
        "purpose": "Non-fatal restore anomalies reported by restored_update.",
    },
    "restoreInitialStepMonitor": {
        "family": "restore_state",
        "purpose": "Initial restore step monitor state.",
    },
    "restoreRetryStepMonitor": {
        "family": "restore_state",
        "purpose": "Retry restore step monitor state.",
    },
    "restoreInitialStepNames": {
        "family": "restore_state",
        "purpose": "Initial restore step names.",
    },
    "restoreInitialStepIDs": {
        "family": "restore_state",
        "purpose": "Initial restore step identifiers.",
    },
    "restoreInitialStepResults": {
        "family": "restore_state",
        "purpose": "Initial restore step results.",
    },
    "restoreInitialStepWarnings": {
        "family": "restore_state",
        "purpose": "Initial restore step warnings.",
    },
    "restoreInitialStepCodes": {
        "family": "restore_state",
        "purpose": "Initial restore step codes.",
    },
    "restoreInitialStepDomains": {
        "family": "restore_state",
        "purpose": "Initial restore step domains.",
    },
    "restoreInitialStepError": {
        "family": "restore_state",
        "purpose": "Initial restore step error.",
    },
    "restoreRetryStepNames": {
        "family": "restore_state",
        "purpose": "Retry restore step names.",
    },
    "restoreRetryStepIDs": {
        "family": "restore_state",
        "purpose": "Retry restore step identifiers.",
    },
    "restoreRetryStepResults": {
        "family": "restore_state",
        "purpose": "Retry restore step results.",
    },
    "restoreRetryStepWarnings": {
        "family": "restore_state",
        "purpose": "Retry restore step warnings.",
    },
    "restoreRetryStepCodes": {
        "family": "restore_state",
        "purpose": "Retry restore step codes.",
    },
    "restoreRetryStepDomains": {
        "family": "restore_state",
        "purpose": "Retry restore step domains.",
    },
    "restoreRetryStepError": {
        "family": "restore_state",
        "purpose": "Retry restore step error.",
    },
    "restoreRebootRetryEnabled": {
        "family": "restore_state",
        "purpose": "Reboot retry is enabled for restore.",
    },
    "restoreRebootRetryZone": {
        "family": "restore_state",
        "purpose": "Restore reboot retry zone.",
    },
    "recovery_mode": {
        "family": "restore_state",
        "purpose": "Recovery-mode marker used by restored_update.",
    },
    "recovery_mode_on_reboot_retry": {
        "family": "restore_state",
        "purpose": "Recovery-mode marker used after reboot retry.",
    },
}

RESTORE_OPTION_CATALOG = {
    "RecoveryOSFailureIsFatal": {
        "group": "recoveryos",
        "stability_relevance": "critical",
        "description": "Treat RecoveryOS failure as fatal to the restore flow.",
    },
    "RetainRecoveryOS": {
        "group": "recoveryos",
        "stability_relevance": "important",
        "description": "Keep the RecoveryOS container after restore.",
    },
    "RecoveryOSOnly": {
        "group": "recoveryos",
        "stability_relevance": "critical",
        "description": "Perform only the RecoveryOS portion of the flow.",
    },
    "InstallRecoveryOS": {
        "group": "recoveryos",
        "stability_relevance": "critical",
        "description": "Install the RecoveryOS payload during restore.",
    },
    "ForceInstallRecoveryOS": {
        "group": "recoveryos",
        "stability_relevance": "critical",
        "description": "Force RecoveryOS installation even when the flow would skip it.",
    },
    "AuthInstallRecoveryOSVariant": {
        "group": "recoveryos",
        "stability_relevance": "informational",
        "description": "RecoveryOS variant selection used by authinstall.",
    },
    "RecoveryOSBundlePath": {
        "group": "recoveryos",
        "stability_relevance": "informational",
        "description": "Path to the RecoveryOS bundle.",
    },
    "RecoveryOSVersionData": {
        "group": "recoveryos",
        "stability_relevance": "informational",
        "description": "Version payload for RecoveryOS.",
    },
    "PostRestoreAction": {
        "group": "post_restore",
        "stability_relevance": "important",
        "description": "Action to perform after restore completes.",
    },
    "restoreRebootRetryEnabled": {
        "group": "reboot_retry",
        "stability_relevance": "critical",
        "description": "Enable reboot retry handling during restore.",
    },
    "restoreRebootRetryZone": {
        "group": "reboot_retry",
        "stability_relevance": "important",
        "description": "Restrict the reboot retry zone.",
    },
}


class RestoreOptions:
    def __init__(
        self,
        firmware_preflight_info=None,
        sep=None,
        macos_variant=None,
        build_identity: BuildIdentity = None,
        restore_boot_args=None,
        spp=None,
        restore_behavior: Optional[str] = None,
        msp=None,
    ):
        self.AutoBootDelay = 0

        try:
            if firmware_preflight_info is not None:
                bbus = dict(firmware_preflight_info)
                bbus.pop("FusingStatus")
                bbus.pop("PkHash")
                self.BBUpdaterState = bbus

                nonce = firmware_preflight_info.get("Nonce")
                if nonce is not None:
                    self.BasebandNonce = nonce
        except KeyError as e:
            logger.warning(f"Skipping addition of firmware_preflight_info due to: {e}")

        self.SupportedDataTypes = SUPPORTED_DATA_TYPES
        self.SupportedMessageTypes = SUPPORTED_MESSAGE_TYPES

        # FIXME: Should be adjusted for update behaviors
        if macos_variant:
            self.AddSystemPartitionPadding = True
            self.AllowUntetheredRestore = False
            self.AuthInstallEnableSso = False

            macos_variant = build_identity.macos_variant
            if macos_variant is not None:
                self.AuthInstallRecoveryOSVariant = macos_variant

            self.AuthInstallRestoreBehavior = restore_behavior
            self.AutoBootDelay = 0
            self.BasebandUpdaterOutputPath = True
            self.DisableUserAuthentication = True
            self.FitSystemPartitionToContent = True
            self.FlashNOR = True
            self.FormatForAPFS = True
            self.FormatForLwVM = False
            self.InstallDiags = False
            self.InstallRecoveryOS = True
            self.MacOSSwapPerformed = True
            self.MacOSVariantPresent = True
            self.MinimumBatteryVoltage = 0  # FIXME: Should be adjusted for M1 macbooks (if needed)
            self.RecoveryOSUnpack = True
            self.ShouldRestoreSystemImage = True
            self.SkipPreflightPersonalization = False
            self.UpdateBaseband = True

            # FIXME: I don't know where this number comes from yet.
            #  It seems like it matches this part of the build identity:
            # 	<key>OSVarContentSize</key>
            # 	<integer>573751296</integer>
            # It did work with multiple macOS versions
            self.recoveryOSPartitionSize = 58201
            if msp:
                self.SystemPartitionSize = msp
        else:
            self.BootImageType = "UserOrInternal"
            self.DFUFileType = "RELEASE"
            self.DataImage = False
            self.FirmwareDirectory = "."
            self.FlashNOR = True
            self.KernelCacheType = "Release"
            self.NORImageType = "production"
            self.RestoreBundlePath = "/tmp/Per2.tmp"
            self.SystemImageType = "User"
            self.UpdateBaseband = False

            # Added for iOS 18.0 beta1
            self.HostHasFixFor99053849 = True
            self.SystemImageFormat = "AEAWrappedDiskImage"
            self.WaitForDeviceConnectionToFinishStateMachine = False
            self.SupportedAsyncDataTypes = {
                "BasebandData": False,
                "RecoveryOSASRImage": False,
                "StreamedImageDecryptionKey": False,
                "SystemImageData": False,
                "URLAsset": True,
            }

            if sep is not None:
                required_capacity = sep.get("RequiredCapacity")
                if required_capacity:
                    logger.debug(f"TZ0RequiredCapacity: {required_capacity}")
                    self.TZ0RequiredCapacity = required_capacity

            self.PersonalizedDuringPreflight = True

        self.RootToInstall = False
        self.UUID = str(uuid.uuid4()).upper()
        self.CreateFilesystemPartitions = True
        self.SystemImage = True

        if restore_boot_args is not None:
            self.RestoreBootArgs = restore_boot_args

        if spp:
            spp = dict(spp)
        else:
            spp = {
                "1024": 1280,
                "128": 1280,
                "16": 160,
                "256": 1280,
                "32": 320,
                "512": 1280,
                "64": 640,
                "768": 1280,
                "8": 80,
            }
        self.SystemPartitionPadding = spp

    def to_dict(self):
        return self.__dict__


def _normalize_restore_options(options):
    if options is None:
        return {}
    if isinstance(options, dict):
        return options
    if hasattr(options, "to_dict"):
        return options.to_dict()
    return dict(options)


def _summarize_restore_value(value) -> dict:
    if isinstance(value, dict):
        return {
            "kind": "dict",
            "item_count": len(value),
            "keys": sorted(str(key) for key in value),
        }
    if isinstance(value, list):
        return {
            "kind": "list",
            "item_count": len(value),
        }
    if isinstance(value, tuple):
        return {
            "kind": "tuple",
            "item_count": len(value),
        }
    if isinstance(value, str):
        line_count = 0 if not value else value.count("\n") + 1
        return {
            "kind": "string",
            "char_count": len(value),
            "line_count": line_count,
        }
    if isinstance(value, bool):
        return {
            "kind": "bool",
            "value": value,
        }
    if value is None:
        return {
            "kind": "none",
        }
    return {
        "kind": type(value).__name__,
        "value": value,
    }


def summarize_restore_message_type(message_type: Optional[str]) -> dict:
    if message_type is None:
        return {
            "checked": False,
            "reason": "No restore message type was provided.",
        }

    canonical_type = message_type
    if message_type == "CheckpointMsg":
        canonical_type = "Checkpoint"

    catalog_entry = RESTORE_MESSAGE_CATALOG.get(canonical_type) or RESTORE_MESSAGE_CATALOG.get(message_type)
    result = {
        "checked": True,
        "message_type": message_type,
        "canonical_type": canonical_type,
        "family": catalog_entry["family"] if catalog_entry else "unknown",
        "purpose": catalog_entry["purpose"] if catalog_entry else "unknown",
    }
    if message_type != canonical_type:
        result["alias_of"] = canonical_type
    return result


def summarize_restore_message(message: dict) -> dict:
    message_type = message.get("MsgType")
    summary = summarize_restore_message_type(message_type)
    summary["message_keys"] = sorted(str(key) for key in message)
    return summary


def summarize_restore_message_details(message: dict) -> dict:
    summary = summarize_restore_message(message)
    details = {}
    state = {}

    status = message.get("Status")
    if isinstance(status, int):
        details["status"] = {
            "kind": "int",
            "value": status,
            "success": status == 0,
        }

    log = message.get("Log")
    if isinstance(log, str):
        details["log"] = _summarize_restore_value(log)

    previous_restore_log = message.get("PreviousRestoreLog")
    if isinstance(previous_restore_log, str):
        details["previous_restore_log"] = _summarize_restore_value(previous_restore_log)

    for key in sorted(message):
        if key == "MsgType":
            continue
        if key in RESTORE_MESSAGE_STATE_KEYS:
            state[key] = {
                **RESTORE_MESSAGE_STATE_KEYS[key],
                "value_summary": _summarize_restore_value(message[key]),
            }

    if details:
        summary["details"] = details
    if state:
        summary["state"] = state
    return summary


def summarize_restore_options(options) -> dict:
    normalized = _normalize_restore_options(options)
    summary = {
        "checked": True,
        "option_count": len(normalized),
        "known_options": {},
        "unknown_options": {},
        "stability": {
            "recoveryos_required": False,
            "recoveryos_failure_fatal": None,
            "retains_recoveryos": None,
            "recoveryos_only": None,
            "install_recoveryos": None,
            "force_install_recoveryos": None,
            "reboot_retry_enabled": None,
            "reboot_retry_zone": None,
        },
        "notes": [],
    }

    for key, value in normalized.items():
        if key in RESTORE_OPTION_CATALOG:
            summary["known_options"][key] = {
                "value": value,
                **RESTORE_OPTION_CATALOG[key],
            }
        else:
            summary["unknown_options"][key] = value

    stability = summary["stability"]
    for key in (
        "RecoveryOSFailureIsFatal",
        "RetainRecoveryOS",
        "RecoveryOSOnly",
        "InstallRecoveryOS",
        "ForceInstallRecoveryOS",
        "restoreRebootRetryEnabled",
        "restoreRebootRetryZone",
    ):
        if key in normalized:
            stability_key = {
                "RecoveryOSFailureIsFatal": "recoveryos_failure_fatal",
                "RetainRecoveryOS": "retains_recoveryos",
                "RecoveryOSOnly": "recoveryos_only",
                "InstallRecoveryOS": "install_recoveryos",
                "ForceInstallRecoveryOS": "force_install_recoveryos",
                "restoreRebootRetryEnabled": "reboot_retry_enabled",
                "restoreRebootRetryZone": "reboot_retry_zone",
            }[key]
            stability[stability_key] = normalized[key]

    if stability["recoveryos_failure_fatal"] is False:
        summary["notes"].append("RecoveryOS failure is non-fatal; the device may finish without RecoveryOS.")
    if stability["recoveryos_only"] is True:
        summary["notes"].append("RecoveryOSOnly is set; the flow is intentionally limited to RecoveryOS.")
    if stability["install_recoveryos"] is True or stability["force_install_recoveryos"] is True:
        summary["notes"].append("RecoveryOS installation is explicitly requested.")
    if stability["retains_recoveryos"] is True:
        summary["notes"].append("RecoveryOS is retained after restore.")
    if stability["reboot_retry_enabled"] is True:
        summary["notes"].append("Reboot retry is enabled.")
    if stability["reboot_retry_zone"] is not None:
        summary["notes"].append(f"Reboot retry zone: {stability['reboot_retry_zone']}")

    summary["stability"]["recoveryos_required"] = any(
        stability[key] is True for key in ("recoveryos_only", "install_recoveryos", "force_install_recoveryos")
    )
    return summary
