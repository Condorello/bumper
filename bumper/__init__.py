"""Init module."""
import asyncio
import logging
import os
import socket
import sys

from bumper.db import (
    bot_reset_connection_status,
    client_reset_connection_status,
    revoke_expired_oauths,
    revoke_expired_tokens,
)
from bumper.mqtt.helper_bot import HelperBot
from bumper.mqtt.server import MQTTServer
from bumper.util import get_logger, log_to_stdout
from bumper.web.server import WebServer, WebserverBinding
from bumper.xmppserver import XMPPServer


def strtobool(strbool: str | bool | None) -> bool:
    """Convert str to bool."""
    if str(strbool).lower() in ["true", "1", "t", "y", "on", "yes"]:
        return True
    else:
        return False


# os.environ['PYTHONASYNCIODEBUG'] = '1' # Uncomment to enable ASYNCIODEBUG
bumper_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

# Set defaults from environment variables first
# Folders
if not log_to_stdout:
    logs_dir = os.environ.get("BUMPER_LOGS") or os.path.join(bumper_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)  # Ensure logs directory exists or create
data_dir = os.environ.get("BUMPER_DATA") or os.path.join(bumper_dir, "data")
os.makedirs(data_dir, exist_ok=True)  # Ensure data directory exists or create
certs_dir = os.environ.get("BUMPER_CERTS") or os.path.join(bumper_dir, "certs")
os.makedirs(certs_dir, exist_ok=True)  # Ensure data directory exists or create

# Certs
ca_cert = os.environ.get("BUMPER_CA") or os.path.join(certs_dir, "ca.crt")
server_cert = os.environ.get("BUMPER_CERT") or os.path.join(certs_dir, "bumper.crt")
server_key = os.environ.get("BUMPER_KEY") or os.path.join(certs_dir, "bumper.key")

# Listeners
bumper_listen = os.environ.get("BUMPER_LISTEN") or socket.gethostbyname(
    socket.gethostname()
)

bumper_announce_ip = os.environ.get("BUMPER_ANNOUNCE_IP") or bumper_listen

# Other
bumper_debug = strtobool(os.environ.get("BUMPER_DEBUG")) or False
use_auth = False
token_validity_seconds = 3600  # 1 hour
oauth_validity_days = 15
bumper_proxy_mqtt = strtobool(os.environ.get("BUMPER_PROXY_MQTT")) or False
bumper_proxy_web = strtobool(os.environ.get("BUMPER_PROXY_WEB")) or False

mqtt_server: MQTTServer
mqtt_helperbot: HelperBot
web_server: WebServer
xmpp_server: XMPPServer

shutting_down = False

bumperlog = get_logger("bumper")
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)  # Ignore this logger

web_server_https_port = os.environ.get("WEB_SERVER_HTTPS_PORT") or 443
mqtt_listen_port = 8883
xmpp_listen_port = 5223
web_server_bindings = [
    WebserverBinding(bumper_listen, int(web_server_https_port), True),
    WebserverBinding(bumper_listen, 8007, False),
]


async def start() -> None:
    """Start bumper."""
    # Reset xmpp/mqtt to false in database for bots and clients
    bot_reset_connection_status()
    client_reset_connection_status()

    try:
        loop = asyncio.get_event_loop()
    except:  # noqa: E722
        loop = asyncio.new_event_loop()

    if bumper_debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] :: %(levelname)s :: %(name)s :: %(module)s :: %(funcName)s :: %(lineno)d :: %(message)s",
        )
        loop.set_debug(True)  # Set asyncio loop to debug
        # logging.getLogger("asyncio").setLevel(logging.DEBUG)  # Show debug asyncio logs (disabled in init, uncomment for debugging asyncio)
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] :: %(levelname)s :: %(name)s :: %(message)s",
        )

    if not bumper_listen:
        bumperlog.fatal("No listen address configured")
        return

    if not (
        os.path.exists(ca_cert)
        and os.path.exists(server_cert)
        and os.path.exists(server_key)
    ):
        bumperlog.fatal("Certificate(s) don't exist at paths specified")
        return

    bumperlog.info("Starting Bumper")

    if bumper_proxy_mqtt:
        bumperlog.info("Proxy MQTT Enabled")
    if bumper_proxy_web:
        bumperlog.info("Proxy Web Enabled")

    global mqtt_server
    mqtt_server = MQTTServer(bumper_listen, mqtt_listen_port)
    global mqtt_helperbot
    mqtt_helperbot = HelperBot(bumper_listen, mqtt_listen_port)
    global web_server
    web_server = WebServer(web_server_bindings, bumper_proxy_web, bumper_debug)
    global xmpp_server
    xmpp_server = XMPPServer(bumper_listen, xmpp_listen_port)

    # Start XMPP Server
    asyncio.create_task(xmpp_server.start_async_server())

    # Start MQTT Server
    # await start otherwise we get an error connecting the helper bot
    await mqtt_server.start()
    while not mqtt_server.state == "started":
        await asyncio.sleep(0.1)

    # Start MQTT Helperbot
    await mqtt_helperbot.start()

    # Start web servers
    await web_server.start()

    bumperlog.info("Bumper started successfully")
    # Start maintenance
    while not shutting_down:
        asyncio.create_task(maintenance())
        await asyncio.sleep(5)


async def maintenance() -> None:
    """Run maintenance."""
    revoke_expired_tokens()
    revoke_expired_oauths()


async def shutdown() -> None:
    """Shutdown bumper (safe even if startup failed midway)."""
    global shutting_down
    shutting_down = True

    bumperlog.info("Shutting down")

    # Helper: recupera oggetti globali senza NameError se non inizializzati
    mh = globals().get("mqtt_helperbot", None)
    ws = globals().get("web_server", None)
    ms = globals().get("mqtt_server", None)
    xs = globals().get("xmpp_server", None)

    # 1) MQTT helperbot
    try:
        if mh is not None:
            await mh.disconnect()
    except Exception:
        bumperlog.exception("Error while disconnecting mqtt_helperbot")

    # 2) Web server
    try:
        if ws is not None:
            await ws.shutdown()
    except Exception:
        bumperlog.exception("Error while shutting down web_server")

    # 3) MQTT server
    try:
        if ms is not None:
            while getattr(ms, "state", None) == "starting":
                await asyncio.sleep(0.1)
            if getattr(ms, "state", None) == "started":
                await ms.shutdown()
    except Exception:
        bumperlog.exception("Error while shutting down mqtt_server")

    # 4) XMPP server
    try:
        if xs is not None and getattr(xs, "server", None):
            if xs.server.is_serving:
                xs.server.close()
            await xs.server.wait_closed()
    except Exception:
        bumperlog.exception("Error while shutting down xmpp_server")

    bumperlog.info("Shutdown complete")


def main(argv: None | list[str] = None) -> None:
    """Start everything."""
    import argparse

    global bumper_debug
    global bumper_listen
    global bumper_announce_ip
    if not argv:
        argv = sys.argv[1:]  # Set argv to argv[1:] if not passed into main
    try:

        if not (
            os.path.exists(ca_cert)
            and os.path.exists(server_cert)
            and os.path.exists(server_key)
        ):
            msg = "No certs found! Please generate them (More infos in the docs)"
            bumperlog.fatal(msg)
            sys.exit(msg)

        if not (os.path.exists(os.path.join(data_dir, "passwd"))):
            with open(os.path.join(data_dir, "passwd"), "w"):
                pass

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--listen", type=str, default=None, help="start serving on address"
        )
        parser.add_argument(
            "--announce",
            type=str,
            default=None,
            help="announce address to bots on checkin",
        )
        parser.add_argument("--debug", action="store_true", help="enable debug logs")

        args = parser.parse_args(args=argv)

        if args.debug:
            bumper_debug = True

        if args.listen:
            bumper_listen = args.listen

        if args.announce:
            bumper_announce_ip = args.announce

        asyncio.run(start())

    except KeyboardInterrupt:
        bumperlog.info("Keyboard Interrupt!")
        pass

    except Exception as e:
        bumperlog.exception(e)
        pass

    finally:
        asyncio.run(shutdown())
