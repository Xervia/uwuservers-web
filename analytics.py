from datetime import datetime
import json


class Analytics:
    def __init__(self):
        self.file = './analytics.json'
        self.analytics = {}
        self.analytic_max = 720
        
        self.all_keys = [
            "actions_per_day",
            "registration_per_day",
            "login_per_day",
            "delete_user_per_day",
            "recover_user_per_day",
            "banned_user_per_day",
            "unbanned_user_per_day",
        ]  
        self.default_analytic = {
            "max": self.analytic_max,
            "current": 0,
            "total": 0,
            "data": [],
        }
        
        self.load()
      
    def default(self):
        data = {}

        for key in self.all_keys:
            data[key] = self.default_analytic

        return {
            # Get the current day, month, and year formatted as a string
            "last_push": datetime.now().strftime("%d-%m-%Y"),
            "data": data
        }

    def load(self):
        try:
            with open(self.file, 'r') as f:
                self.analytics = json.load(f)

            for key in self.all_keys:
                if key not in self.analytics['data']:
                    self.analytics['data'][key] = self.default_analytic
            
            for key in self.all_keys:
                self.analytics['data'][key]['max'] = self.analytic_max

            self.save()
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
        days_passed = (datetime.strptime(
            current_date, "%d-%m-%Y") - last_push).days

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
        analytic['total'] += 1
        self.save()

    def decrement(self, key):
        analytic = self.get()['data'][key]
        analytic['current'] -= 1
        analytic['total'] -= 1
        self.save()

    def get(self):
        self.check()
        return self.analytics
