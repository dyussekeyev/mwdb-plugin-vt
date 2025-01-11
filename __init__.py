import logging

from mwdb.core.plugins import PluginAppContext, PluginHookHandler
from mwdb.model import File

__author__ = "Askar Dyussekeyev"
__version__ = "0.0.1"
__doc__ = "Simple plugin for mwdb-core that requests a file report from VirusTotal"


logger = logging.getLogger("mwdb.plugin.virustotal")


config_api_key = ""


def VtProcessFile(file: File):
    file.add_comment(f"VirusTotal results:")
    
    pass


class VtHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        logger.info("on_created_file() - File report requested", file.file_name)
        VtProcessFile(file)

    def on_reuploaded_file(self, file: File):
        logger.info("on_reuploaded_file() - File report requested", file.file_name)
        VtProcessFile(file)


def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.

    This will be called on app load.
    """
    app_context.register_hook_handler(VtHookHandler)
    logger.info("Plugin hook handler is registered.")


__plugin_entrypoint__ = entrypoint
