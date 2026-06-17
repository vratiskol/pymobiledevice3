from pymobiledevice3 import irecv
from pymobiledevice3.irecv import IRecv, Mode


class FakeUsbConfiguration:
    bConfigurationValue = 1


class FakeRecoveryUsbDevice:
    manufacturer = "Apple Inc."
    idProduct = Mode.RECOVERY_MODE_2.value
    serial_number = (
        "SDOM:01 CPID:8120 CPRV:11 CPFM:03 SCEP:01 BDID:08 "
        "ECID:0123456789ABCDEF IBFL:3D SIKA:00 SRNM:[PYMD3TEST0]"
    )

    def __init__(self):
        self.altsettings = []

    def get_active_configuration(self):
        return FakeUsbConfiguration()

    def set_configuration(self, configuration=None):
        self.configuration = configuration

    def set_interface_altsetting(self, interface=None, alternate_setting=None):
        self.altsettings.append((interface, alternate_setting))


def test_irecv_accepts_cli_hex_string_ecid(monkeypatch):
    device = FakeRecoveryUsbDevice()

    monkeypatch.setattr(irecv, "find", lambda find_all=True: [device])
    monkeypatch.setattr(irecv, "get_string", lambda usb_device, index: "")

    client = IRecv(ecid="0x123456789abcdef", timeout=0.01)

    assert client.ecid == 0x123456789ABCDEF
    assert client.mode == Mode.RECOVERY_MODE_2


def test_irecv_accepts_bare_hex_string_ecid(monkeypatch):
    device = FakeRecoveryUsbDevice()

    monkeypatch.setattr(irecv, "find", lambda find_all=True: [device])
    monkeypatch.setattr(irecv, "get_string", lambda usb_device, index: "")

    client = IRecv(ecid="0123456789ABCDEF", timeout=0.01)

    assert client.ecid == 0x123456789ABCDEF
