from threads import Threads
from time import sleep
import datetime
import os

class Backup:
    def __init__(self):
        self.path = './backups'
        self.file = 'api.db'
        self.name = 'api'
        self.last_backup = None
        self.backup_interval = 60 * 60 * 24
        self.max_backups = 10
        self.threads = Threads()
        
        self.threads.append(self.run)()
    
    def run(self):
        while True:
            if self.last_backup is None or datetime.datetime.now().timestamp() - self.last_backup >= self.backup_interval:
                self.backup()
            sleep(60)

    def backup(self):
        backups = os.listdir(self.path)
        if len(backups) >= self.max_backups:
            os.remove(f'{self.path}/{backups[0]}')
        
        backup_timestamp = datetime.datetime.now().timestamp()
        backup_timestamp_readable = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        backup_name = f'{self.name}_{backup_timestamp}.db'
        
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        
        with open(f'{self.path}/{backup_name}', 'wb') as f:
            with open(f'{self.file}', 'rb') as f2:
                f.write(f2.read())
        
        self.last_backup = backup_timestamp

    def restore(self):
        backups = os.listdir(self.path)
        if len(backups) == 0:
            return False
        
        backup = backups[-1]
        
        with open(f'{self.path}/{backup}', 'rb') as f:
            with open(f'{self.file}', 'wb') as f2:
                f2.write(f.read())
        
        return True