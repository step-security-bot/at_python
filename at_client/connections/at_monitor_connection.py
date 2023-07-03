import ssl
from threading import Thread
import time

from at_client.common.atsign import AtSign
from at_client.util.sync_decorator import synchronized
from .atconnection import AtConnection
from .address import Address
from at_client.connections.atsecondaryconnection import AtSecondaryConnection


class AtMonitorConnection(AtSecondaryConnection):
    last_received_time: int = 0
    running: bool = False
    should_be_running: bool = False
    
    def __init__(self, atsign:AtSign, address: Address, context:ssl.SSLContext=ssl.create_default_context(), verbose:bool=False):
        self.atsign = atsign
        super().__init__(address.host, address.port, context, verbose)
        self._last_heartbeat_sent_time = int(time.time() * 1000)
        self._last_heartbeat_ack_time = int(time.time() * 1000)
        self._heartbeat_interval_millis = 30000
        t1 = Thread(target=self.start_heart_beat())
        t1.start()
       
    
    def start_heart_beat(self):
        while True:
            if self.should_be_running:
                if (not self.running) or (self._last_heartbeat_sent_time - self._last_heartbeat_ack_time >= self._heartbeat_interval_millis):
                    try:
                        print("Monitor heartbeats not being received")
                        # stop_monitor()
                        wait_start_time = int(time.time() * 1000)
                        while self.running and (int(time.time() * 1000) - wait_start_time < 5000):
                            # Wait 5 seconds for monitor to stop
                            try:
                                time.sleep(1)
                            except Exception as ignore:
                                pass
                            if self.running:
                                print("Monitor thread has not stopped, but going to start another one anyway")
                            # start_monitor()
                    except Exception as e:
                        print("Monitor restart failed "+ str(e))  
                else:
                    if int(time.time() * 1000) - self._last_heartbeat_sent_time > self._heartbeat_interval_millis:
                        try:
                            self.execute_command(command="noop:0", retry_on_exception=False, read_the_response=False)
                            self._last_heartbeat_sent_time = int(time.time() * 1000)
                        except Exception as ignore:
                            # Can't do anything, the heartbeat loop will take care of restarting the monitor connection
                            pass
                try:
                    time.sleep(self._heartbeat_interval_millis / 5000) # 5 * 1000 (from ms to s)
                except Exception as ignore:
                    pass
                
    @synchronized
    def start_monitor(self):
        self._last_heartbeat_sent_time = self._last_heartbeat_ack_time = int(time.time() * 1000)
        
        self.should_be_running = True
        if not self.running:
            self.running = True
            if not self._connected:
                try:
                    self.connect()
                except Exception as e:
                    print("startMonitor failed to connect to secondary : " + str(e))
                    self.running = False
                    return False
            # nuevo thread que ejecute "run"
            t1 = Thread(target=self.run())
            t1.start()
        return True
    
    @synchronized
    def stop_monitor(self):
        self.should_be_running = False
        self._last_heartbeat_sent_time = self._last_heartbeat_ack_time = int(time.time() * 1000)
        self.disconnect()
        
    async def run(self):
        what = ""
        try:
            monitor_cmd = "monitor:" + self.last_received_time
            what = "send monitor command " + monitor_cmd
            self.execute_command(command=monitor_cmd, retry_on_exception=True, read_the_response=False)
            
            while self.should_be_running and (not self._stream_reader.at_eof):
                what = "read from connection"
                response = await self._stream_reader.readline()
                if self._verbose:
                    print("\tRCVD (MONITOR): " + str(response))
                # event_type and map of event data
                what = "parse monitor message"
                
                # TODO: parse monitor message
                
        except Exception as e:
            if not self.should_be_running:
                print("shouldBeRunning is false, and monitor has stopped OK. Exception was : " + str(e))
            else:
                print("Monitor failed to " + what + " : " + str(e))
                print("Monitor ending. Monitor heartbeat thread should restart the monitor shortly")
                self.disconnect()
        finally:
            self.running = False
            self.disconnect()