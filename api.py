from base64 import re, b64decode, decode, encode, b64encode
from flask import cli, app, Flask, request, jsonify
from result import result, error, checkJson
from hashlib import new, sha512, sha256
from datetime import date, datetime
from ipRatelimit import ratelimit
from analytics import Analytics
from backupApi import Backup
from threads import Threads
from mc_auth import mcAuth
import requests
import secrets
import string
import json
import re
import os


class PERMISSIONS:
    GUEST = 0
    MODERATOR = 1
    ADMIN = 2
    
class ViolationDangerZones:
    GOOD = 0
    OKAY = 1
    BAD = 2
    DANGER = 3
    BANNED = 4


print("API v1 loaded")


class Api:
    def __init__(self, app):
        self.data = {}
        self.dp = "./api.db"
        self.dp_backup = "./api_backup.db"
        self.uri = "/api/v1/"
        self.check_uuid_uri = "https://mcuuid.net/?q="
        self.cdn_uri = "https://cdn.uwuservers.com/api/v2/"

        self.ratelimit = ratelimit()
        self.threads = Threads()

        self.load_db()
        self.mcAuth = mcAuth()
        self.backup = Backup()
        self.analytics = Analytics()
        
        # Login/Register user with uuid and name/password
        @app.route(self.get_uri("login"), methods=["POST"])
        def login():
            def _():
                data = checkJson([[{"value": "uuid", "type": str}, {"value": "password", "type": str}], [{"value": "mc_auth", "type": dict}]])
                if 'error' in data:
                    return error(data['error'])
                
                name = None
                
                if 'mc_auth' in data:
                    mc_auth_data = self.mcAuth.proxy(data['mc_auth'])
                    if 'error' in mc_auth_data:
                        return error(mc_auth_data['error'], mc_auth_data['status'])
                
                    name = self.checkMcAuth(mc_auth_data)
                    if 'error' in name:
                        return error(name['error'], 400)
                    
                    data['uuid'] = mc_auth_data['uuid']
                else:
                    name = self.checkUUIDAndFetchName(data['uuid'])
                    if 'error' in name:
                        return error(name['error'], 400)
                
                newbie = False
                if not self.userExists(data['uuid']):
                    registeredUser = self.register_user(data['uuid'], name)
                    data['password'] = registeredUser['credentials']['password']
                    registeredUser['credentials']['password'] = sha512(registeredUser['credentials']['password'].encode()).hexdigest()
                    self.update_credentials(registeredUser['credentials'])
                    self.analytics.increment('registration_per_day')
                    newbie = True
                    
                if 'password' not in data:
                    return result(data['uuid'], 200)
                
                uuid, password = data['uuid'], data['password']
                data = self.login(uuid, password)
                if data is None:
                    return error('invalid_credentials', 401)
                
                self.data['credentials'][uuid]['password'] = sha512(password.encode()).hexdigest()
                
                self.analytics.increment('actions_per_day')
                self.analytics.increment('login_per_day')
                
                res = {
                    "newbie": newbie,
                    "data": data,
                }

                return result(res, 200)
            return self.ratelimit.request(_)

        # Get analytics
        @app.route(self.get_uri("analytics"), methods=["GET"])
        def getAnalytics():
            def _():
                self.analytics.check()
                return result(self.analytics.get(), 200)
            return self.ratelimit.request(_)

        # Get analytics by key
        @app.route(self.get_uri("analytics/<key>"), methods=["GET"])
        def getAnalyticsByKey(key):
            def _():
                self.analytics.check()

                if key not in self.analytics.get()["data"].keys():
                    return error('key_not_found', 404)

                return result(self.analytics.get(), 200)
            return self.ratelimit.request(_)

        # Get user by UUID
        @app.route(self.get_uri("user/<uuid>"), methods=["GET"])
        def getUser(uuid):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)
                
                return result(self.data["users"][uuid], 200)
            return self.ratelimit.request(_)

        # Get user permissions by UUID
        @app.route(self.get_uri("user/<uuid>/permissions"), methods=["GET"])
        def getUserPermissions(uuid):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                return result(self.data["users"][uuid]["permissions"], 200)
            return self.ratelimit.request(_)

        # Check user permission by UUID
        @app.route(self.get_uri("user/<uuid>/permissions/<permission>"), methods=["GET"])
        def checkUserPermission(uuid, permission):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                return result(int(permission) in self.data["users"][uuid]["permissions"], 200)
            return self.ratelimit.request(_)

        # Get user name by UUID
        @app.route(self.get_uri("user/<uuid>/name"), methods=["GET"])
        def getUserName(uuid):
            def _():
                name = self.checkUUIDAndFetchName(uuid)

                if 'error' in name:
                    return error(name['error'], 400)

                return result(name, 200)
            return self.ratelimit.request(_)

        # Delete user by token
        @app.route(self.get_uri("user/<uuid>"), methods=["DELETE"])
        def deleteUser(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = getUserByUUID(uuid)
                if not self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)

                requests.delete(f"{self.cdn_uri}server/{uuid}")

                if tokenUser['uuid'] != uuid:
                    self.append_action(uuid, "delete_user", {
                        "by": tokenUser["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(tokenUser["uuid"], "delete_user", {
                    "of": uuid,
                    "ip": request.remote_addr,
                })

                self.data["users"][uuid]["deleted"] = True
                self.data["users"][uuid]["deletedTimestamp"] = datetime.now().timestamp()

                self.analytics.increment("actions_per_day")
                self.analytics.increment("delete_user_per_day")
                self.save_db()
                
                return result("User deleted: " + uuid, 200)
            return self.ratelimit.request(_)

        # Get user credentials by token
        @app.route(self.get_uri("user/<uuid>/credentials"), methods=["GET"])
        def getCredentials(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.getUserByUUID(uuid)
                if self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)

                selfanalytics.increment("actions_per_day")
                self.save_db()

                return result(self.getCredentials(uuid), 200)
            return self.ratelimit.request(_)

        # Get user by token
        @app.route(self.get_uri("user"), methods=["GET"])
        def getUserByToken():
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)
                
                self.analytics.increment("actions_per_day")
                self.save_db()

                return result(self.user_tree(tokenUser, self.getCredentials(tokenUser['uuid'])), 200)
            return self.ratelimit.request(_)

        # Get actions of user by token
        @app.route(self.get_uri("actions/<uuid>"), methods=["GET"])
        def getActions(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.getUserByUUID(uuid)
                if tokenUser != uuidUser and PERMISSIONS.ADMIN not in tokenUser["permissions"]:
                    return jsonify({"error": "Unauthorized"}), 403

                actions = self.get_actions(uuid)

                if tokenUser['uuid'] != uuid:
                    self.append_action(uuid, "get_actions", {
                        "by": tokenUser["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(tokenUser["uuid"], "get_actions", {
                    "of": uuid,
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result(actions, 200)
            return self.ratelimit.request(_)

        # Append action to user by token
        @app.route(self.get_uri("actions/<uuid>"), methods=["POST"])
        def appendAction(uuid):
            def _():
                data = checkJson([[{"value": "action", "type": str}, {"value": "data", "type": dict}]])
                if 'error' in data:
                    return error(data['error'])
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.getUserByUUID(uuid)
                if self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN]):
                    return jsonify({"error": "Unauthorized"}), 403

                self.append_action(uuid, data["action"], data["data"])
                self.analytics.increment("actions_per_day")
                self.save_db()

                return result("Action appended", 200)
            return self.ratelimit.request(_)

        # Add permission to a user by token (only admin)
        @app.route(self.get_uri("user/<uuid>/permissions"), methods=["POST"])
        def addPermission(uuid):
            def _():
                data = checkJson([[{"value": "permission", "type": int}]])
                if 'error' in data:
                    return error(data['error'])
                
                if not self.ckeckIfPermissionExists(data["permission"]):
                    return error('permission_not_found', 404)
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)
                
                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.data["users"][uuid]
                if not self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)

                if data["permission"] in uuidUser["permissions"]:
                    return error('permission_already_exists', 400)

                uuidUser["permissions"].append(data["permission"])
                self.update_user(uuidUser)

                if tokenUser['uuid'] != uuid:
                    self.append_action(uuid, "add_permission", {
                        "by": tokenUser["uuid"],
                        "permission": data["permission"],
                        "ip": request.remote_addr,
                    })
                self.append_action(tokenUser["uuid"], "add_permission", {
                    "of": uuid,
                    "permission": data["permission"],
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result(self.getUserByUUID(uuid), 200)
            return self.ratelimit.request(_)

        # Remove permission from a user by token (only admin)
        @app.route(self.get_uri("user/<uuid>/permissions"), methods=["DELETE"])
        def removePermission(uuid):
            def _():
                data = checkJson([[{"value": "permission", "type": int}]])
                if 'error' in data:
                    return error(data['error'])
                
                if not self.ckeckIfPermissionExists(data["permission"]):
                    return error('permission_not_found', 404)
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.data["users"][uuid]
                if self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)

                if data["permission"] not in uuidUser["permissions"]:
                    return error('permission_not_found', 404)
                
                if len(uuidUser["permissions"]) == 1:
                    return error('last_permission', 400)

                uuidUser["permissions"].remove(data["permission"])
                self.update_user(uuidUser)

                if tokenUser['uuid'] != uuid:
                    self.append_action(uuid, "remove_permission", {
                        "by": tokenUser["uuid"],
                        "permission": data["permission"],
                        "ip": request.remote_addr,
                    })
                self.append_action(tokenUser["uuid"], "remove_permission", {
                    "of": uuid,
                    "permission": data["permission"],
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result(self.getUserByUUID(uuid), 200)
            return self.ratelimit.request(_)

        # Change user password by token (only admin)
        @app.route(self.get_uri("user/<uuid>/password"), methods=["POST"])
        def changePassword(uuid):
            def _():
                data = checkJson([[{"value": "password", "type": str}]])
                if 'error' in data:
                    return error(data['error'])
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                tokenUser = self.getUserByToken(token)
                if 'error' in tokenUser:
                    return error(tokenUser['error'], 401)

                uuidUser = self.data["users"][uuid]
                if not self.checkPermissions(tokenUser, uuidUser, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)

                token_data = self.generate_credentials(uuid, data["password"])
                cred = self.data["credentials"][uuid]
                cred["password"] = token_data["password"]
                cred["token"] = token_data["token"]
                cred["salt"] = token_data["salt"]
                self.update_credentials(cred)

                if tokenUser['uuid'] != uuid:
                    self.append_action(uuid, "change_password", {
                        "by": tokenUser["uuid"],
                        "ip": request.remote_addr
                    })
                self.append_action(tokenUser["uuid"], "change_password", {
                    "of": uuid,
                    "ip": request.remote_addr
                })

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result("Password changed", 200)
            return self.ratelimit.request(_)

        @app.route(self.get_uri(), methods=["GET", "POST", "PUT", "DELETE"])
        @app.route(self.get_uri("<first>"), methods=["GET", "POST", "PUT", "DELETE"])
        @app.route(self.get_uri("<first>/<path:rest>"), methods=["GET", "POST", "PUT", "DELETE"])
        def api(first="", rest=""):
            def _():
                return jsonify({"message": "UwU Servers User API v1"}), 200
            return self.ratelimit.request(_)
    
    def banUser(self, uuid, reason):
        if not self.userExists(uuid):
            return None
        
        user = self.data["users"][uuid]
        user["moderation"]["banned"]["value"] = True
        user["moderation"]["banned"]["reason"] = reason
        user["moderation"]["banned"]["timestamp"] = datetime.now().timestamp()
        self.update_user(user)
        
        lastLoginAction = [ action for action in self.get_actions(uuid)["data"] if action["action"] == "login" ][-1]
        ip = lastLoginAction["data"]["ip"]
        self.ratelimit.ban_ip(ip)
    
    def ckeckIfPermissionExists(self, permission):
        return permission in [PERMISSIONS.GUEST, PERMISSIONS.MODERATOR, PERMISSIONS.ADMIN]
    
    def userExists(self, uuid):
        return uuid in self.data["users"]
    
    def checkPermissions(self, user, target, permissions, onlyPermissions=False):
        if not onlyPermissions and user["uuid"] == target["uuid"]:
            return True
        for permission in permissions:
            if permission in user["permissions"]:
                return True
        return False

    def getCredentials(self, uuid):
        if uuid not in self.data["credentials"]:
            return None
        return self.data["credentials"][uuid]
    
    def getUserByUUID(self, uuid):
        if uuid not in self.data["users"]:
            return None
        return self.data["users"][uuid]  

    def getUserByToken(self, token):
        for cred in self.data["credentials"].values():
            if cred["token"] == token:
                return self.getUserByUUID(cred["uuid"])
        return { "error": "invalid_token" }

    def generate_action(self, action, data):
        return {
            "action": action,
            "data": data,
            "timestamp": datetime.now().timestamp(),
        }

    def get_actions(self, uuid):
        if uuid not in self.data["actions"]:
            return None

        return self.data["actions"][uuid]

    def append_action(self, uuid, action, data):
        actions = self.get_actions(uuid)
        actions["data"].append(self.generate_action(action, data))
        actions["data"] = actions["data"][-30:]
        self.update_user_action(actions)
        
    def checkMcAuth(self, data):
        name = self.checkUUIDAndFetchName(data['uuid'])
        if 'error' in name:
            return name['error']
        elif name != data['name']:
            return { 'error': 'name_mismatch' }
        return name

    def checkUUIDAndFetchName(self, uuid):
        response = requests.get(f"{self.check_uuid_uri}{uuid}")

        if response.status_code != 200:
            return { 'error': 'uuid_not_found' }

        html = response.text
        site_name = re.search(
            r'results_username" class="w-full bg-gray-100 border border-gray-300 text-gray-900 p-2 rounded focusable" readonly="readonly" value="([a-zA-Z0-9_]+)"></td>', html)
        site_uuid = re.search(r'results_raw_id".+value="([a-f0-9-]+)', html)

        if (not site_uuid or site_uuid.group(1) != uuid) or not site_name:
            return { 'error': 'uuid_not_found' }

        return site_name.group(1)

    def get_uri(self, route=""):
        return f"{self.uri}{route}"
    
    def default_data(self):
        return {
            "actions": {},
            "users": {},
            "credentials": {}
        }

    def load_db(self):
        if not os.path.exists(self.dp) or os.path.getsize(self.dp) == 0:
            self.data = self.default_data()
            self.save_db()

        with open(self.dp, "r") as f:
            self.data = json.load(f)

        default_data = self.default_data()
        default_keys = default_data.keys()
        default_values = default_data.values()

        self.data = self.walkthrough(self.data, default_data)
        self.save_db()

    # Walk through the whole default data and add missing keys
    def walkthrough(self, data, default_data):
        for key, value in default_data.items():
            if key not in data:
                data[key] = value
            elif type(value) == dict:
                data[key] = self.walkthrough(data[key], value)
        return data

    def save_db(self):
        with open(self.dp_backup, "w") as f:
            json.dump(self.data, f)
        with open(self.dp, "w") as f:
            json.dump(self.data, f)

    def user_tree(self, user, cred):
        return {
            "user": user,
            "credentials": cred,
        }

    def login(self, uuid, password):
        if uuid not in self.data["users"]:
            return None

        user = self.data["users"][uuid]
        cred = self.data["credentials"][uuid]

        cred_compare = self.generate_credentials(uuid, password, cred["salt"])

        if cred_compare["token"] != cred["token"]:
            return None

        user["last_login_timestamp"] = datetime.now().timestamp()
        self.update_user(user)

        ip = request.remote_addr
        agent = request.headers.get("User-Agent")
        data = {
            "ip": ip,
            "agent": agent,
        }

        self.append_action(uuid, "login", data)
        self.save_db()

        return self.user_tree(user, cred)

    def register_user(self, uuid, name):
        user = self.generate_user(uuid, name)
        cred = self.generate_credentials(uuid)
        acti = self.generate_user_action(uuid)
        self.update_user(user)
        self.update_credentials(cred)
        self.update_user_action(acti)

        self.append_action(uuid, "register", {})
        self.save_db()

        return self.user_tree(user, cred)

    def update_user(self, user):
        self.data["users"][user["uuid"]] = user

    def remove_user(self, uuid):
        if uuid not in self.data["users"]:
            return None

        del self.data["users"][uuid]
        del self.data["credentials"][uuid]

    def update_credentials(self, cred):
        self.data["credentials"][cred["uuid"]] = cred

    def update_user_action(self, actions):
        self.data["actions"][actions["uuid"]] = actions

    def generate_user_action(self, uuid):
        return {
            "uuid": uuid,
            "data": [],
        }

    def generate_user(self, uuid, name):
        return {
            "uuid": uuid,
            "name": name,
            "created_timestamp": datetime.now().timestamp(),
            "last_login_timestamp": None,
            "permissions": [
                PERMISSIONS.GUEST,
            ],
            "moderation": {
                "banned": {
                    "value": False,
                    "reason": None,
                    "timestamp": None,
                },
                "deleted": {
                    "value": False,
                    "reason": None,
                    "timestamp": None,    
                },
            },
            "violations": {
                "total": 0,
                "danger": ViolationDangerZones.GOOD,
                "list": [],  
            },
        }

    def generate_credentials(self, uuid, password=None, salt=None):
        encodedUUID = b64encode(uuid.encode()).decode()

        alphabet = string.ascii_letters + string.digits
        password = password or ''.join(
            secrets.choice(alphabet) for i in range(16))
        encodedPassword = b64encode(password.encode()).decode()

        encodedTotal = f"{encodedUUID}:{encodedPassword}"
        salt = salt or os.urandom(16).hex() + os.urandom(16).hex()
        token = sha512(f"{encodedTotal}{salt}".encode()).hexdigest()

        return {
            "uuid": uuid,
            "password": password,
            "token": token,
            "salt": salt,
        }
# 751