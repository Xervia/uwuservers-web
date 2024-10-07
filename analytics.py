from datetime import datetime
import json

class Analytics:
    def __init__(self):
        self.file = './analytics.json'
        self.analytics = {}
        self.load()

    def default(self):
        return {
            # Get the current day, month, and year formatted as a string
            "last_push": datetime.now().strftime("%d-%m-%Y"),
            "data": {
                "actions_per_day": {
                    "max": 720,
                    "current": 0,
                    "data": [],
                },
                "registration_per_day": {
                    "max": 720,
                    "current": 0,
                    "data": [],
                },
                "login_per_day": {
                    "max": 720,
                    "current": 0,
                    "data": [],
                },
                "delete_user_per_day": {
                    "max": 720,
                    "current": 0,
                    "data": [],
                }
            }
        }

    def load(self):
        try:
            with open(self.file, 'r') as f:
                self.analytics = json.load(f)
        except:
            self.analytics = self.default()
            self.save()

    def save(self):
        with open(self.file, 'w') as f:
            json.dump(self.analytics, f)
            
    def check(self):
        analytics = self.analytics
        
        last_push = datetime.strptime(analytics['last_push'], "%d-%m-%Y")
        current_date = datetime.now().strftime("%d-%m-%Y")
        days_passed = (datetime.strptime(current_date, "%d-%m-%Y") - last_push).days
        
        if days_passed > 0:
            for _ in range(days_passed):
                for key in analytics['data'].keys():
                    data = analytics["data"][key]
                    data["data"].append(data["current"])
                    data["data"] = data["data"][-data["max"]:]
                    data["current"] = 0
        
            analytics['last_push'] = current_date
    
    def increment(self, key):
        analytic = self.get()['data'][key]
        analytic['current'] += 1
        self.save()
    
    def decrement(self, key):
        analytic = self.get()['data'][key]
        analytic['current'] -= 1
        self.save()

    def get(self):
        self.check()
        return self.analytics