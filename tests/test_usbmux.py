import socket

from pymobiledevice3.usbmux import PlistMuxConnection, list_usb_device_inventory


def test_plist_mux_ignores_paired_message() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        mux = PlistMuxConnection(sock)
        mux._process_device_state({"DeviceID": 28, "MessageType": "Paired"})
        assert mux.devices == []
    finally:
        sock.close()


def _write(path, value):
    path.write_text(f"{value}\n")


def _write_apple_device_sysfs(tmp_path):
    device = tmp_path / "1-2"
    device.mkdir()
    _write(device / "idVendor", "05AC")
    _write(device / "idProduct", "12A8")
    _write(device / "manufacturer", "Apple Inc.")
    _write(device / "product", "iPhone")
    _write(device / "serial", "00008120000E65841122201E")
    _write(device / "busnum", "1")
    _write(device / "devnum", "106")
    _write(device / "speed", "480")
    _write(device / "version", " 2.10")
    _write(device / "bConfigurationValue", "4")
    _write(device / "configuration", "PTP + Apple Mobile Device + Apple USB Ethernet")
    _write(device / "bNumConfigurations", "4")
    _write(device / "bNumInterfaces", " 3")

    ptp = tmp_path / "1-2:4.0"
    ptp.mkdir()
    _write(ptp / "interface", "PTP")
    _write(ptp / "bInterfaceNumber", "00")
    _write(ptp / "bAlternateSetting", "0")
    _write(ptp / "bInterfaceClass", "06")
    _write(ptp / "bInterfaceSubClass", "01")
    _write(ptp / "bInterfaceProtocol", "01")
    _write(ptp / "bNumEndpoints", "03")
    _write(ptp / "modalias", "usb:v05ACp12A8ic06isc01ip01in00")

    mux = tmp_path / "1-2:4.1"
    mux.mkdir()
    _write(mux / "interface", "Apple USB Multiplexor")
    _write(mux / "bInterfaceNumber", "01")
    _write(mux / "bAlternateSetting", "0")
    _write(mux / "bInterfaceClass", "ff")
    _write(mux / "bInterfaceSubClass", "fe")
    _write(mux / "bInterfaceProtocol", "02")
    _write(mux / "bNumEndpoints", "02")

    ethernet = tmp_path / "1-2:4.2"
    ethernet.mkdir()
    _write(ethernet / "interface", "AppleUSBEthernet")
    _write(ethernet / "bInterfaceNumber", "02")
    _write(ethernet / "bAlternateSetting", "1")
    _write(ethernet / "bInterfaceClass", "ff")
    _write(ethernet / "bInterfaceSubClass", "fd")
    _write(ethernet / "bInterfaceProtocol", "01")
    _write(ethernet / "bNumEndpoints", "02")
    net = ethernet / "net"
    net.mkdir()
    (net / "eth-test").mkdir()
    return device


def _descriptor_blob():
    device = bytes([18, 1, 0x10, 0x02, 0, 0, 0, 64, 0xAC, 0x05, 0xA8, 0x12, 0x04, 0x15, 1, 2, 3, 4])
    ptp_config = bytes([9, 2, 18, 0, 1, 1, 5, 0xC0, 250])
    ptp_interface = bytes([9, 4, 0, 0, 0, 0x06, 0x01, 0x01, 15])
    mux_config = bytes([9, 2, 25, 0, 1, 4, 8, 0xC0, 250])
    mux_interface = bytes([9, 4, 1, 0, 1, 0xFF, 0xFE, 0x02, 21])
    mux_endpoint = bytes([7, 5, 0x85, 2, 0, 2, 0])
    return device + ptp_config + ptp_interface + mux_config + mux_interface + mux_endpoint


def test_usb_device_inventory_parses_linux_sysfs(tmp_path) -> None:
    _write_apple_device_sysfs(tmp_path)

    non_apple = tmp_path / "1-3"
    non_apple.mkdir()
    _write(non_apple / "idVendor", "1d6b")

    devices = list_usb_device_inventory(tmp_path)

    assert len(devices) == 1
    assert devices[0].vendor_id == "05ac"
    assert devices[0].product_id == "12a8"
    assert devices[0].configuration_value == 4
    assert devices[0].matches_udid("00008120-000E65841122201E")
    assert [interface.role for interface in devices[0].interfaces] == ["ptp", "usbmux", "network"]
    assert devices[0].interfaces[1].alias == "AppleUSBMux"
    assert devices[0].interfaces[2].network_interfaces == ["eth-test"]
    assert devices[0].interfaces[2].network_state == []


def test_usb_device_inventory_can_include_non_apple_devices(tmp_path) -> None:
    device = tmp_path / "1-1"
    device.mkdir()
    _write(device / "idVendor", "1d6b")
    _write(device / "idProduct", "0002")

    assert list_usb_device_inventory(tmp_path) == []
    assert list_usb_device_inventory(tmp_path, vendor_id=None)[0].vendor_id == "1d6b"


def test_usb_device_inventory_can_include_network_state(tmp_path) -> None:
    _write_apple_device_sysfs(tmp_path)
    net_sysfs = tmp_path / "class-net"
    net_device = net_sysfs / "eth-test"
    net_device.mkdir(parents=True)
    _write(net_device / "address", "c6:52:4f:33:26:e6")
    _write(net_device / "operstate", "down")
    _write(net_device / "carrier", "0")
    _write(net_device / "mtu", "1500")

    devices = list_usb_device_inventory(
        tmp_path,
        include_network_state=True,
        net_sysfs_path=net_sysfs,
        include_ip_command=False,
    )

    state = devices[0].interfaces[2].network_state[0]
    assert state.name == "eth-test"
    assert state.mac_address == "c6:52:4f:33:26:e6"
    assert state.operstate == "down"
    assert state.carrier is False
    assert state.mtu == 1500
    assert state.addresses == []


def test_usb_device_inventory_can_include_configuration_descriptors(tmp_path) -> None:
    device = _write_apple_device_sysfs(tmp_path)
    (device / "descriptors").write_bytes(_descriptor_blob())

    devices = list_usb_device_inventory(tmp_path, include_configuration_descriptors=True)

    configurations = devices[0].available_configurations
    assert [configuration.value for configuration in configurations] == [1, 4]
    assert configurations[0].interfaces[0].alias == "PTP"
    assert configurations[1].interfaces[0].alias == "AppleUSBMux"
    assert configurations[1].interfaces[0].role == "usbmux"
    assert configurations[1].interfaces[0].endpoints[0].to_dict()["address"] == "0x85"
