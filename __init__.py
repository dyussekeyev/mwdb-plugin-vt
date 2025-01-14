import logging
import requests
from datetime import datetime

from mwdb.core.plugins import PluginAppContext, PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

__author__ = "Askar Dyussekeyev"
__version__ = "0.1.0"
__doc__ = "Simple plugin for mwdb-core that requests a file report from VirusTotal"


logger = logging.getLogger("mwdb.plugin.virustotal")


config_api_url = ""
config_api_key = ""
config_vt_api_key = ""


def VtProcessFile(sha256):
    mwdb = MWDB(api_url=config_api_url, api_key=config_api_key)
    
    file = mwdb.query_file(sha256)
       
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": config_vt_api_key})
    
    if response.status_code == 200:
        data = response.json()["data"]
        attributes = data["attributes"]
        
        comment = f"""
        VT Link: https://www.virustotal.com/gui/file/{sha256]}
        
        malicious: {attributes['last_analysis_stats']['malicious']}
        suspicious: {attributes['last_analysis_stats']['suspicious']}
        undetected: {attributes['last_analysis_stats']['undetected']}
        harmless: {attributes['last_analysis_stats']['harmless']}
        
        first_submission_date: {datetime.utcfromtimestamp(attributes['first_submission_date']).strftime('%Y-%m-%d %H:%M:%S UTC')}
        last_submission_date: {datetime.utcfromtimestamp(attributes['last_submission_date']).strftime('%Y-%m-%d %H:%M:%S UTC')}
        last_analysis_date: {datetime.utcfromtimestamp(attributes['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        """

        for engine, result in attributes['last_analysis_results'].items():
            if result['category'] in ['malicious', 'suspicious']:
                comment += f"{engine}: {result['result']}\n"

        comment += f"""
        unique_sources: {attributes['unique_sources']}
        reputation: {attributes['reputation']}
        times_submitted: {attributes['times_submitted']}
        """
        
        file.add_comment(comment.strip())
    else:
        error = response.json().get("error", {})
        code = error.get("code", "Unknown")
        message = error.get("message", "No message provided")
        logger.info("VirusTotal error: %s %s for sha256 = %s", code, message, sha256)


class VtHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        logger.info("on_created_file(): File report requested for sha256 = %s", file.sha256)
        VtProcessFile(file.sha256)

    def on_reuploaded_file(self, file: File):
        logger.info("on_reuploaded_file(): File report requested for sha256 = %s", file.sha256)
        VtProcessFile(file.sha256)


def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.

    This will be called on app load.
    """
    app_context.register_hook_handler(VtHookHandler)
    logger.info("Plugin hook handler is registered.")


__plugin_entrypoint__ = entrypoint
