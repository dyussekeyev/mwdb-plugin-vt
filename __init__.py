import logging

from mwdb.core.plugins import PluginAppContext, PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

__author__ = "Askar Dyussekeyev"
__version__ = "0.0.1"
__doc__ = "Simple plugin for mwdb-core that requests a file report from VirusTotal"


logger = logging.getLogger("mwdb.plugin.virustotal")


config_api_url = ""
config_api_key = ""


def VtProcessFile(sha256):
    mwdb = MWDB(api_url=config_api_url, api_key=config_api_key)
    
    file = mwdb.query_file(sha256)
    file.add_comment("VirusTotal results:")

    pass


class VtHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        logger.info("on_created_file() - File report requested (sha256 = %s)", file.sha256)
        VtProcessFile(file.sha256)

    def on_reuploaded_file(self, file: File):
        logger.info("on_reuploaded_file() - File report requested (sha256 = %s)", file.sha256)
        VtProcessFile(file.sha256)


def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.

    This will be called on app load.
    """
    app_context.register_hook_handler(VtHookHandler)
    logger.info("Plugin hook handler is registered.")


__plugin_entrypoint__ = entrypoint
