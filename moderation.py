from datetime import datetime
import json
import os


class Moderation:
    def __init__(self, api):
        self.api = api
        self.file = './moderation.json'
        self.actions = []

        self.moderation_keys = [
            "banned",
            "deleted",
        ]
        
        self.load()
    
    def load(self):
        try:
            if not os.path.exists(self.file):
                self.save()
                return
            
            with open(self.file, 'r') as f:
                self.actions = json.load(f)
        except:
            self.actions = self.default()
            self.save()
    
    def save(self):
        with open(self.file, 'w') as f:
            json.dump(self.actions, f)
    
    def appendAction(self, user_id, target_id, type, mod):
        action = {
            "user_id": user_id,
            "target_id": target_id,
            "type": type,
            "value": mod['value'],
            "total": mod['total'],
            "timestamp": mod['timestamp'],
        }

        self.actions.append(action)
        self.save()

    def default(self):
        data = {}

        for key in self.moderation_keys:
            data[key] = {
                "value": False,
                "reason": None,
                "timestamp": None,
                "total": 0,
            }

        return data

    def getUserModeration(self, user, mod=None):
        if mod: return user['moderation'][mod]
        return user['moderation']

    def banUser(self, user_id, target_id, reason):
        if not self.api.userExists(target_id):
            return None

        user = self.api.getUserByUUID(target_id)
        mod = self.getUserModeration(user, 'banned')
        
        if mod['value']:
            return 'user_already_banned'

        mod['value'] = True
        mod['reason'] = reason
        mod['timestamp'] = datetime.now().timestamp()
        mod['total'] += 1
        
        user['moderation']['banned'] = mod
        self.api.update_user(user)
        
        lastLoginIp = user['last_login_ip']
        registrationIp = user['registration_ip']
        # self.api.ratelimit.ban_ip(lastLoginIp)
        # self.api.ratelimit.ban_ip(registrationIp)
        
        self.appendAction(user_id, target_id, 'ban', mod)
    
    def unbanUser(self, user_id, target_id):
        if not self.api.userExists(target_id):
            return 'user_does_not_exist'
        
        user = self.api.getUserByUUID(target_id)
        mod = self.getUserModeration(user, 'banned')
        
        if not mod['value']:
            return 'user_not_banned'
        
        mod['value'] = False
        mod['reason'] = None
        mod['timestamp'] = None
        
        user['moderation']['banned'] = mod
        self.api.update_user(user)
        
        lastLoginIp = user['last_login_ip']
        registrationIp = user['registration_ip']
        # self.api.ratelimit.unban_ip(lastLoginIp)
        
        self.appendAction(user_id, target_id, 'unban', mod)
    
    def deleteUser(self, user_id, target_id):
        if not self.api.userExists(target_id):
            return 'user_does_not_exist'
        
        user = self.api.getUserByUUID(target_id)
        mod = self.getUserModeration(user, 'deleted')
        
        if mod['value']:
            return 'user_already_deleted'
        
        mod['value'] = True
        mod['reason'] = None
        mod['timestamp'] = datetime.now().timestamp()
        mod['total'] += 1
        
        user['moderation']['deleted'] = mod
        self.api.update_user(user)
        
        self.appendAction(user_id, target_id, 'delete', mod)
    
    def recoverUser(self, user_id, target_id):
        if not self.api.userExists(target_id):
            return 'user_does_not_exist'
        
        user = self.api.getUserByUUID(target_id)
        mod = self.getUserModeration(user, 'deleted')
        
        if not mod['value']:
            return 'user_not_deleted'
        
        mod['value'] = False
        mod['reason'] = None
        mod['timestamp'] = None
        
        user['moderation']['deleted'] = mod
        self.api.update_user(user)
        
        self.appendAction(user_id, target_id, 'recover', mod)
        
    def isUserBanned(self, uuid):
        return self.getUserModeration(self.api.getUserByUUID(uuid), 'banned')['value']
    
    def isUserDeleted(self, uuid):
        return self.getUserModeration(self.api.getUserByUUID(uuid), 'deleted')['value']