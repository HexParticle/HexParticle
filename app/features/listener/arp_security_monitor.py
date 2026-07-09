from PyQt6.QtCore import QObject, pyqtSignal

import app_ctx
from hexlib import arp_cache, ip_int_to_str, mac_to_str


class ArpSecurityMonitor(QObject):
    alert_triggered = pyqtSignal(dict)


    def __init__(self, ctx: app_ctx.AppContext):
        super().__init__()
        self.__ctx = ctx

        self.__c_callback_ref = arp_cache.ARP_ALERT_CALLBACK_TYPE(self.__internal_alert_callback)
        self.__ctx._lib.lib.register_arp_alert_callback(self.__c_callback_ref)


    def __internal_alert_callback(self, alert_ptr):
        if not alert_ptr:
            return

        alert_data = alert_ptr.contents
        
        alert_payload = {
            "ip": ip_int_to_str(alert_data.ip_address),
            "cached_mac": mac_to_str(alert_data.cached_mac),
            "poison_mac": mac_to_str(alert_data.poison_mac)
        }
        
        self.alert_triggered.emit(alert_payload)