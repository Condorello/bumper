"""Server module."""
import os
from typing import Any
from importlib.metadata import entry_points

import amqtt
from amqtt.broker import BrokerContext
from amqtt.mqtt.constants import QOS_0, QOS_1, QOS_2
from amqtt.session import IncomingApplicationMessage, Session
from passlib.apps import custom_app_context as pwd_context

import bumper
from bumper import dns
from bumper.db import (
    bot_add,
    bot_get,
    bot_set_mqtt,
    check_authcode,
    client_add,
    client_get,
    client_set_mqtt,
)
from bumper.mqtt.helper_bot import HELPER_BOT_CLIENT_ID
from bumper.mqtt.proxy import _LOGGER as _LOGGER_PROXY
from bumper.mqtt.proxy import ProxyClient
from bumper.util import get_logger

_LOGGER = get_logger("mqtt_server")
_LOGGER_MESSAGES = get_logger("mqtt_messages")


def _ensure_broker_plugin_entrypoint() -> None:
    """
    Ensure the 'bumper' broker plugin is discoverable by amqtt via entry-points.

    amqtt loads broker plugins from the entry-point group: 'amqtt.broker.plugins'
    Name must match what you put in config['auth']['plugins'] (here: 'bumper').
    """
    try:
        eps = entry_points(group="amqtt.broker.plugins")
    except TypeError:
        # Very old importlib.metadata API fallback (unlikely on Py3.12, but safe)
        eps = entry_points().get("amqtt.broker.plugins", [])  # type: ignore[assignment]

    if not any(ep.name == "bumper" for ep in eps):
        raise RuntimeError(
            "Bumper MQTT plugin entry-point not found.\n"
            "You must register it in your package metadata (pyproject.toml/setup.cfg), e.g.:\n"
            "[project.entry-points.\"amqtt.broker.plugins\"]\n"
            "bumper = \"bumper.mqtt.server:BumperMQTTServerPlugin\"\n"
        )


class MQTTServer:
    """Mqtt server."""

    def __init__(self, host: str, port: int, **kwargs: dict[str, Any]) -> None:
        try:
            self._host = host
            self._port = port

            # For file auth, set user:hash in passwd file see
            # (https://hbmqtt.readthedocs.io/en/latest/references/hbmqtt.html#configuration-example)
            passwd_file = kwargs.get(
                "password_file", os.path.join(os.path.join(bumper.data_dir, "passwd"))
            )
            allow_anon = kwargs.get("allow_anonymous", False)

            # Clean approach: rely on proper package entry-point registration
            _ensure_broker_plugin_entrypoint()

            # Initialize bot server
            config = {
                "listeners": {
                    "default": {"type": "tcp"},
                    "tcp-tsl": {
                        "bind": f"{host}:{port}",
                        "ssl": "on",
                        "certfile": bumper.server_cert,
                        "keyfile": bumper.server_key,
                    },
                    "tcp-insecure": {
                        "bind": f"{host}:1883",
                    },
                },
                "sys_interval": 0,
                "auth": {
                    "allow-anonymous": allow_anon,
                    "password-file": passwd_file,
                    "plugins": [
                        "bumper"
                    ],  # must match entry-point name in 'amqtt.broker.plugins'
                },
                "topic-check": {
                    "enabled": True,  # Workaround until https://github.com/Yakifo/amqtt/pull/93 is merged
                    "plugins": [],
                },
            }

            self._broker = amqtt.broker.Broker(config=config)

        except Exception:
            _LOGGER.exception("An exception occurred during initialize", exc_info=True)
            raise

    @property
    def state(self) -> amqtt.broker.Broker.states:
        """Return the state of the broker."""
        return self._broker.transitions.state

    @property
    def sessions(self) -> list[Session]:
        """Get sessions."""
        # pylint: disable-next=protected-access
        return [session for (session, _) in self._broker._sessions.values()]

    async def start(self) -> None:
        """Start MQTT server."""
        _LOGGER.info("Starting MQTT Server at %s:%d", self._host, self._port)
        try:
            await self._broker.start()
        except Exception:
            _LOGGER.exception("An exception occurred during startup", exc_info=True)
            raise

    async def shutdown(self) -> None:
        """Shutdown server."""
        # stop session handler manually otherwise connection will not be closed correctly
        for (_, handler) in self._broker._sessions.values():  # pylint: disable=protected-access
            await handler.stop()
        await self._broker.shutdown()


def _log__helperbot_message(custom_log_message: str, topic: str, data: str) -> None:
    _LOGGER_MESSAGES.debug(
        "%s - Topic: %s - Message: %s", custom_log_message, topic, data
    )


class BumperMQTTServerPlugin:
    """MQTT Server plugin which handles the authentication."""

    def __init__(self, context: BrokerContext) -> None:
        self._proxy_clients: dict[str, ProxyClient] = {}
        self.context = context
        try:
            self.auth_config = self.context.config["auth"]
            self._users = self._read_password_file()

        except KeyError:
            self.context.logger.warning(
                "'bumper' section not found in context configuration"
            )
        except Exception:
            _LOGGER.exception(
                "An exception occurred during plugin initialization", exc_info=True
            )
            raise

    async def authenticate(self, session: Session, **kwargs: dict[str, Any]) -> bool:
        """Authenticate session."""
        username = session.username
        password = session.password
        client_id = session.client_id

        try:
            if client_id == HELPER_BOT_CLIENT_ID:
                _LOGGER.info("Bumper Authentication Success - Helperbot")
                return True

            if "@" in client_id:
                client_id_split = str(client_id).split("@")
                client_details_split = client_id_split[1].split("/")
                if "ecouser" not in client_id_split[1]:
                    # if ecouser aren't in details it is a bot
                    bot_add(
                        username,
                        client_id_split[0],
                        client_details_split[0],
                        client_details_split[1],
                        "eco-ng",
                    )
                    _LOGGER.info(
                        "Bumper Authentication Success - Bot - SN: %s - DID: %s - Class: %s",
                        username,
                        client_id_split[0],
                        client_details_split[0],
                    )

                    if bumper.bumper_proxy_mqtt:
                        mqtt_server = await dns.resolve("mq-ww.ecouser.net")
                        _LOGGER_PROXY.info(
                            "MQTT Proxy Mode - Using server %s for client %s",
                            mqtt_server,
                            client_id,
                        )
                        proxy = ProxyClient(
                            client_id, mqtt_server, config={"check_hostname": False}
                        )
                        self._proxy_clients[client_id] = proxy
                        await proxy.connect(username, password)

                    return True

                if check_authcode(client_id_split[0], password) or not bumper.use_auth:
                    client_add(
                        client_id_split[0],
                        client_details_split[0],
                        client_details_split[1],
                    )
                    _LOGGER.info(
                        "Bumper Authentication Success - Client - Username: %s - ClientID: %s",
                        username,
                        client_id,
                    )
                    return True

            # Check for File Auth
            if username:
                # If there is a username and it isn't already authenticated
                password_hash = self._users.get(username, None)
                message_suffix = f"- Username: {username} - ClientID: {client_id}"
                if password_hash:  # If there is a matching entry in passwd, check hash
                    if pwd_context.verify(password, password_hash):
                        _LOGGER.info("File Authentication Success %s", message_suffix)
                        return True

                    _LOGGER.info("File Authentication Failed %s", message_suffix)
                else:
                    _LOGGER.info(
                        "File Authentication Failed - No Entry %s", message_suffix
                    )

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Session: %s", kwargs.get("session", ""), exc_info=True)

        # Check for allow anonymous
        if self.auth_config.get("allow-anonymous", True):
            message = f"Anonymous Authentication Success: config allows anonymous - Username: {username}"
            self.context.logger.debug(message)
            _LOGGER.info(message)
            return True

        return False

    def _read_password_file(self) -> dict[str, str]:
        password_file = self.auth_config.get("password-file", None)
        users: dict[str, str] = {}
        if password_file:
            try:
                with open(password_file, encoding="utf-8") as file:
                    self.context.logger.debug(
                        f"Reading user database from {password_file}"
                    )
                    for line in file:
                        line = line.strip()
                        if not line.startswith("#"):  # Allow comments in files
                            (username, pwd_hash) = line.split(sep=":", maxsplit=3)
                            if username:
                                users[username] = pwd_hash
                                self.context.logger.debug(
                                    f"user: {username} - hash: {pwd_hash}"
                                )
                self.context.logger.debug(
                    f"{(len(users))} user(s) read from file {password_file}"
                )
            except FileNotFoundError:
                self.context.logger.warning(f"Password file {password_file} not found")

        return users

    async def on_broker_client_subscribed(
        self, client_id: str, topic: str, qos: QOS_0 | QOS_1 | QOS_2
    ) -> None:
        """Is called when a client subscribes on the broker."""
        if bumper.bumper_proxy_mqtt:
            if client_id in self._proxy_clients:
                await self._proxy_clients[client_id].subscribe(topic, qos)
                _LOGGER_PROXY.info(
                    "MQTT Proxy Mode - New MQTT Topic Subscription - Client: %s - Topic: %s",
                    client_id,
                    topic,
                )
            elif client_id != HELPER_BOT_CLIENT_ID:
                _LOGGER_PROXY.warning(
                    "MQTT Proxy Mode - No proxy client found! - Client: %s - Topic: %s",
                    client_id,
                    topic,
                )

    async def on_broker_client_connected(self, client_id: str) -> None:
        """On client connected."""
        self._set_client_connected(client_id, True)

    def _set_client_connected(self, client_id: str, connected: bool) -> None:
        didsplit = str(client_id).split("@")

        bot = bot_get(didsplit[0])
        if bot:
            bot_set_mqtt(bot["did"], connected)
            return

        clientresource = didsplit[1].split("/")[1]
        client = client_get(clientresource)
        if client:
            client_set_mqtt(client["resource"], connected)

    async def on_broker_message_received(
        self, message: IncomingApplicationMessage, client_id: str
    ) -> None:
        """On message received."""
        topic = message.topic
        topic_split = str(topic).split("/")
        data_decoded = str(message.data.decode("utf-8"))

        if topic_split[6] == "helperbot":
            _log__helperbot_message("Received Response", topic, data_decoded)
        elif topic_split[3] == "helperbot":
            _log__helperbot_message("Send Command", topic, data_decoded)
        elif topic_split[1] == "atr":
            _log__helperbot_message("Received Broadcast", topic, data_decoded)
        else:
            _log__helperbot_message("Received Message", topic, data_decoded)

        if bumper.bumper_proxy_mqtt and client_id in self._proxy_clients:
            if not topic_split[3] == "proxyhelper":
                if topic_split[6] == "proxyhelper":
                    ttopic = message.topic.split("/")
                    ttopic[6] = self._proxy_clients[client_id].request_mapper.pop(
                        ttopic[10], ""
                    )
                    if ttopic[6] == "":
                        _LOGGER_PROXY.warning(
                            "Request mapper is missing entry, probably request took to"
                            " long... Client_id: %s - Request_id: %s",
                            client_id,
                            ttopic[10],
                        )
                        return

                    ttopic_join = "/".join(ttopic)
                    _LOGGER_PROXY.info(
                        "Bot Message Converted Topic From %s TO %s with message: %s",
                        message.topic,
                        ttopic_join,
                        data_decoded,
                    )
                else:
                    ttopic_join = message.topic
                    _LOGGER_PROXY.info(
                        "Bot Message From %s with message: %s",
                        ttopic_join,
                        data_decoded,
                    )

                try:
                    _LOGGER_PROXY.info(
                        "Proxy Forward Message to Ecovacs - Topic: %s - Message: %s",
                        ttopic_join,
                        data_decoded,
                    )
                    await self._proxy_clients[client_id].publish(
                        ttopic_join, data_decoded.encode(), message.qos
                    )
                except Exception:  # pylint: disable=broad-except
                    _LOGGER_PROXY.error(
                        "Forwarding to Ecovacs - Exception",
                        exc_info=True,
                    )

    async def on_broker_client_disconnected(self, client_id: str) -> None:
        """On client disconnect."""
        if bumper.bumper_proxy_mqtt and client_id in self._proxy_clients:
            await self._proxy_clients.pop(client_id).disconnect()
        self._set_client_connected(client_id, False)
