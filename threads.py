import threading

class Threads:
    def __init__(self):
        self.threads = list()
    
    def append(self, func):
        def wrapper(*args, **kwargs):
            t = threading.Thread(target=func, args=args, kwargs=kwargs)
            t.daemon = True
            t.start()
            
            self.threads.append(t)
            
            return t
        return wrapper

    def kill(self, int):
        thread = self.threads[int]
        thread.join()
        self.threads.remove(thread)
    
    def kill_all(self):
        for thread in self.threads:
            thread.join()
        self.threads.clear()
    
    def get(self, int):
        return self.threads[int]
    
    def get_all(self):
        return self.threads
    
    def get_count(self):
        return len(self.threads)