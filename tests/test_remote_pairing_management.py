import asyncio

from pymobiledevice3.remote.tunnel_service import RemotePairingProtocol


class FakeRemotePairingProtocol(RemotePairingProtocol):
    def __init__(self, response):
        super().__init__()
        self.response = response
        self.requests = []

    async def close(self) -> None:
        pass

    async def receive_response(self) -> dict:
        raise NotImplementedError()

    async def send_request(self, data: dict) -> None:
        raise NotImplementedError()

    async def _send_receive_encrypted_request(self, request: dict) -> dict:
        self.requests.append(request)
        return self.response


def test_remote_pairing_management_request_builds_encrypted_payload():
    protocol = FakeRemotePairingProtocol({"queryUSBConnectedHostTrustState": {"trusted": True}})

    response = asyncio.run(protocol.send_remote_pairing_management_request("queryUSBConnectedHostTrustState"))

    assert protocol.requests == [{"request": {"_0": {"queryUSBConnectedHostTrustState": {}}}}]
    assert response == {"trusted": True}


def test_remote_pairing_management_request_returns_unwrapped_response_when_key_is_unknown():
    protocol = FakeRemotePairingProtocol({"unexpectedResponse": {"value": 1}})

    response = asyncio.run(protocol.send_remote_pairing_management_request("queryUSBConnectedHostTrustState"))

    assert response == {"unexpectedResponse": {"value": 1}}
