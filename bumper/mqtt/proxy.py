"""Mqtt proxy module."""
import asyncio
import ssl
import typing
from collections.abc import MutableMapping
from typing import Any
from urllib.parse import urlparse, urlunparse

import websockets
from amqtt.adapters import (
    StreamReaderAdapter,
    StreamWriterAdapter,
    WebSocketsReader,
    WebSocketsWriter,
)
from amqtt.client import MQTTClient
from amqtt.errors import ConnectError
from amqtt.mqtt.connack import CONNECTION_ACCEPTED
from amqtt.mqtt.constants import QOS_0, QOS_1, QOS_2
from amqtt.mqtt.protocol.client_handler import ClientProtocolHandler

# compat: alcuni rami/vecchie versioni avevano ProtocolHandlerException,
# nelle nuove è ProtocolHandlerError
try:
    from amqtt.errors import ProtocolHandlerError as _ProtocolHandlerError
except Exception:  # pragma: no cover
    _ProtocolHandlerError = Exception  # type: ignore[assignment]

from cachetools import TTLCache
from websockets.exceptions import InvalidHandshake, InvalidURI

import bumper

from ..util import get_logger

_LOGGER = get_logger("mqtt_proxy")

# iot/p2p/[command]]/[sender did]/[sender class]]/[sender resource]
# /[receiver did]/[receiver class]]/[receiver resource]/[q|p/[request id/j
# [q|p] q-> request p-> response


class ProxyClient:
    """Mqtt client, which proxies all messages to the ecovacs servers."""

    def __init__(
        self,
        client_id: str,
        host: str,
        port: int = 443,
        config: dict[str, Any] | None = None,
        timeout: float = 180,
    ):
        self.request_mapper: MutableMapping[str, str] = TTLCache(
            maxsize=int(timeout * timeout), ttl=timeout * 1.1
        )
        self._client = _NoCertVerifyClient(client_id=client_id, config=config)
        self._host = host
        self._port = port

    async def connect(self, username: str, password: str) -> None:
        """Connect."""
        try:
            await self._client.connect(
                f"mqtts://{username}:{password}@{self._host}:{self._port}"
            )
        except Exception:
            _LOGGER.exception("An exception occurred during startup", exc_info=True)
            raise

        asyncio.create_task(self._handle_messages())

    async def _handle_messages(self) -> None:
        while self._client.session.transitions.is_connected():
            try:
                message = await self._client.deliver_message()
                data = message.data.decode("utf-8") if message.data else ""

                _LOGGER.info(
                    "Message Received From Ecovacs - Topic: %s - Message: %s",
                    message.topic,
                    data,
                )
                topic = message.topic
                ttopic = topic.split("/")
                if ttopic[1] == "p2p":
                    if ttopic[3] == "proxyhelper":
                        _LOGGER.error('"proxyhelper" was sender - INVALID!! Topic: %s', topic)
                        continue

                    self.request_mapper[ttopic[10]] = ttopic[3]
                    ttopic[3] = "proxyhelper"
                    topic = "/".join(ttopic)
                    _LOGGER.info("Converted Topic From %s TO %s", message.topic, topic)

                _LOGGER.info(
                    "Proxy Forward Message to Robot - Topic: %s - Message: %s",
                    topic,
                    data,
                )

                bumper.mqtt_helperbot.publish(topic, message.data)
            except Exception:
                _LOGGER.error("An error occurred during handling a message", exc_info=True)

    async def subscribe(self, topic: str, qos: QOS_0 | QOS_1 | QOS_2 = QOS_0) -> None:
        """Subscribe to topic."""
        await self._client.subscribe([(topic, qos)])

    async def disconnect(self) -> None:
        """Disconnect."""
        await self._client.disconnect()

    async def publish(self, topic: str, message: bytes, qos: int | None = None) -> None:
        """Publish message."""
        await self._client.publish(topic, message, qos)


class _NoCertVerifyClient(MQTTClient):  # type:ignore[misc]
    # pylint: disable=all
    """
    Mqtt client, which does not verify the certificate.

    Purpose is only to add:
        sc.verify_mode = ssl.CERT_NONE
    """

    @typing.no_type_check
    async def _connect_coro(self):
        kwargs = dict()

        uri_attributes = urlparse(self.session.broker_uri)
        scheme = uri_attributes.scheme
        secure = True if scheme in ("mqtts", "wss") else False

        self.session.username = (
            self.session.username if self.session.username else uri_attributes.username
        )
        self.session.password = (
            self.session.password if self.session.password else uri_attributes.password
        )
        self.session.remote_address = uri_attributes.hostname
        self.session.remote_port = uri_attributes.port

        if scheme in ("mqtt", "mqtts") and not self.session.remote_port:
            self.session.remote_port = 8883 if scheme == "mqtts" else 1883
        if scheme in ("ws", "wss") and not self.session.remote_port:
            self.session.remote_port = 443 if scheme == "wss" else 80

        if scheme in ("ws", "wss"):
            uri = (
                scheme,
                self.session.remote_address + ":" + str(self.session.remote_port),
                uri_attributes[2],
                uri_attributes[3],
                uri_attributes[4],
                uri_attributes[5],
            )
            self.session.broker_uri = urlunparse(uri)

        self._handler = ClientProtocolHandler(self.plugins_manager)

        if secure:
            sc = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=self.session.cafile,
                capath=self.session.capath,
                cadata=self.session.cadata,
            )
            if "certfile" in self.config and "keyfile" in self.config:
                sc.load_cert_chain(self.config["certfile"], self.config["keyfile"])
            if "check_hostname" in self.config and isinstance(self.config["check_hostname"], bool):
                sc.check_hostname = self.config["check_hostname"]

            sc.verify_mode = ssl.CERT_NONE  # Ignore verify of cert
            kwargs["ssl"] = sc

        try:
            reader = None
            writer = None
            self._connected_state.clear()

            if scheme in ("mqtt", "mqtts"):
                conn_reader, conn_writer = await asyncio.open_connection(
                    self.session.remote_address, self.session.remote_port, **kwargs
                )
                reader = StreamReaderAdapter(conn_reader)
                writer = StreamWriterAdapter(conn_writer)

            elif scheme in ("ws", "wss"):
                websocket = await websockets.connect(
                    self.session.broker_uri,
                    subprotocols=["mqtt"],
                    extra_headers=self.extra_headers,
                    **kwargs,
                )
                reader = WebSocketsReader(websocket)
                writer = WebSocketsWriter(websocket)

            self._handler.attach(self.session, reader, writer)
            return_code = await self._handler.mqtt_connect()

            if return_code is not CONNECTION_ACCEPTED:
                self.session.transitions.disconnect()
                self.logger.warning("Connection rejected with code '%s'", return_code)
                raise ConnectError("Connection rejected by broker")

            await self._handler.start()
            self.session.transitions.connect()
            self._connected_state.set()
            self.logger.debug(
                "connected to %s:%s",
                self.session.remote_address,
                self.session.remote_port,
            )
            return return_code

        except InvalidURI as iuri:
            self.logger.warning("connection failed: invalid URI '%s'", self.session.broker_uri)
            self.session.transitions.disconnect()
            raise ConnectError(f"connection failed: invalid URI '{self.session.broker_uri}'") from iuri

        except InvalidHandshake as ihs:
            self.logger.warning("connection failed: invalid websocket handshake")
            self.session.transitions.disconnect()
            raise ConnectError("connection failed: invalid websocket handshake") from ihs

        except (_ProtocolHandlerError, ConnectionError, OSError) as e:
            self.logger.warning("MQTT connection failed: %r", e)
            self.session.transitions.disconnect()
            raise ConnectError(str(e)) from e
