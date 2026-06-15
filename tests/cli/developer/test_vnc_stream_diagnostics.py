from pymobiledevice3.remote.core_device.vnc_server import (
    _collect_string_markers,
    _media_preflight_diagnostics,
    _stream_config_diagnostics,
)


def test_stream_config_diagnostics_redacts_session_values() -> None:
    diagnostics = _stream_config_diagnostics(
        "video",
        {
            "CustomWidth": 1179,
            "CustomHeight": 2556,
            "SourcePort": 49152,
            "LocalSSRC": 123,
            "RemoteSSRC": 456,
            "RTCPTimeoutEnabled": True,
            "RTCPTimeoutInterval": 20,
            "RxPayloadType": 96,
            "avcMediaStreamOptionClientSessionID": "should-not-leak",
        },
    )

    assert diagnostics == {
        "type": "video",
        "dimensions": {"width": 1179, "height": 2556},
        "payload": {"rx_payload_type": 96, "audio_stream_mode": None, "ltrp_enabled": None},
        "rtcp": {
            "feedback_available": True,
            "source_port_present": True,
            "local_ssrc_present": True,
            "remote_ssrc_present": True,
            "timeout_enabled": True,
            "timeout_interval": 20,
        },
        "present_keys": [
            "CustomHeight",
            "CustomWidth",
            "LocalSSRC",
            "RTCPTimeoutEnabled",
            "RTCPTimeoutInterval",
            "RemoteSSRC",
            "RxPayloadType",
            "SourcePort",
        ],
    }


def test_media_preflight_diagnostics_reports_firmware_markers_without_values() -> None:
    media_support = {
        "features": [
            "com.apple.coredevice.screenViewing",
            {"name": "AVCMediaStreamNegotiatorSettingsCoreDeviceSystemAudio"},
        ],
        "privateDeviceIdentifier": "should-not-leak",
    }
    server_status = {"active": True, "path": "com.apple.coredevice.screenshot"}

    diagnostics = _media_preflight_diagnostics(media_support, server_status, audio_enabled=True)

    assert diagnostics["audio_requested"] is True
    assert diagnostics["media_support"]["available"] is True
    assert diagnostics["media_support"]["top_level_keys"] == ["features", "privateDeviceIdentifier"]
    assert diagnostics["media_support"]["matched_markers"] == ["screen_viewing", "system_audio_negotiator"]
    assert diagnostics["server_status"]["matched_markers"] == ["screenshot"]
    assert "should-not-leak" not in str(diagnostics)


def test_collect_string_markers_finds_nested_keys_and_values() -> None:
    assert _collect_string_markers(
        {
            "AVCMediaStreamNegotiatorSettingsCoreDeviceScreenSharing": {},
            "nested": ["AVCMediaStreamNegotiatorSettingsCoreDeviceMic"],
        },
        {
            "screen": "AVCMediaStreamNegotiatorSettingsCoreDeviceScreenSharing",
            "mic": "AVCMediaStreamNegotiatorSettingsCoreDeviceMic",
        },
    ) == ["mic", "screen"]
