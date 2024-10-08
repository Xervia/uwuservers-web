from base64 import re, b64decode, decode, encode, b64encode
from flask import cli, app, Flask, request, jsonify
from result import result, error, checkJson
from hashlib import new, sha512, sha256
from datetime import date, datetime
from ipRatelimit import ratelimit
from moderation import Moderation
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
    DANGER = 2
    BANNED = 3
    DELETED = 4


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
        self.moderation = Moderation(self)

        # Login/Register user with uuid and name/password
        @app.route(self.get_uri("login"), methods=["POST"])
        def login():
            def _():
                data = checkJson([[{"value": "uuid", "type": str}, {
                                 "value": "password", "type": str}], [{"value": "mc_auth", "type": dict}]])
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
                    registeredUser = self.register_user(data['uuid'], name, isDemo)
                    data['password'] = registeredUser['credentials']['password']
                    registeredUser['credentials']['password'] = sha512(registeredUser['credentials']['password'].encode()).hexdigest()
                    self.update_credentials(registeredUser['credentials'])
                    self.analytics.increment('registration_per_day')
                    newbie = True
                
                user = self.getUserByUUID(data['uuid'])
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_does_not_exist', 403)
                    
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

        # Get analytics (only admin)
        @app.route(self.get_uri("analytics"), methods=["GET"])
        def getAnalytics():
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)
                
                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if not self.checkPermissions(user, user, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)
                
                self.analytics.check()
                return result(self.analytics.get(), 200)
            return self.ratelimit.request(_)

        # Get analytics by key()
        @app.route(self.get_uri("analytics/<key>"), methods=["GET"])
        def getAnalyticsByKey(key):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)
                
                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if not self.checkPermissions(user, user, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)
                
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
                
                user = self.getUserByUUID(uuid)
                if self.moderation.isUserBanned(uuid):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('user_deleted', 403)

                return result(user, 200)
            return self.ratelimit.request(_)

        # Get user permissions by UUID
        @app.route(self.get_uri("user/<uuid>/permissions"), methods=["GET"])
        def getUserPermissions(uuid):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)
                
                user = self.getUserByUUID(uuid)
                if self.moderation.isUserBanned(uuid):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('user_deleted', 403)

                return result(user["permissions"], 200)
            return self.ratelimit.request(_)

        # Check user permission by UUID
        @app.route(self.get_uri("user/<uuid>/permissions/<permission>"), methods=["GET"])
        def checkUserPermission(uuid, permission):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)
                
                user = self.getUserByUUID(uuid)
                if self.moderation.isUserBanned(uuid):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('user_deleted', 403)

                return result(int(permission) in user["permissions"], 200)
            return self.ratelimit.request(_)

        # Get user name by UUID
        @app.route(self.get_uri("user/<uuid>/name"), methods=["GET"])
        def getUserName(uuid):
            def _():
                if not self.userExists(uuid):
                    return error('user_not_found', 404)
                
                user = self.getUserByUUID(uuid)
                if self.moderation.isUserBanned(uuid):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('user_deleted', 403)

                return result(user['name'], 200)
            return self.ratelimit.request(_)

        # Delete user by token
        @app.route(self.get_uri("user/<uuid>"), methods=["DELETE"])
        def deleteUser(uuid):
            def _():
                data = checkJson([[{"value": "reason", "type": str}]])
                if 'error' in data:
                    data = {"reason": "Unknown"}
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)

                requests.delete(f"{self.cdn_uri}server/{uuid}", headers={ "Authorization": token })
                res = self.moderation.deleteUser(user['uuid'], uuid, data['reason'])
                if res: return error(res, 400)
                target['permissions'] = [PERMISSIONS.GUEST]
                self.update_user(user)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "delete_user", {
                        "by": user["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "delete_user", {
                    "of": uuid,
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.analytics.increment("delete_user_per_day")
                self.save_db()

                return result("User deleted: " + uuid, 200)
            return self.ratelimit.request(_)
        
        # Recover user by uuid (only admin)
        @app.route(self.get_uri("user/<uuid>/recover"), methods=["POST"])
        def recoverUser(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)

                target = self.getUserByUUID(uuid)
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)

                res = self.moderation.recoverUser(user['uuid'], uuid)
                if res: return error(res, 400)
                self.update_user(user)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "recover_user", {
                        "by": user["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "recover_user", {
                    "of": uuid,
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.analytics.increment("recover_user_per_day")
                self.save_db()

                return result("User recovered: " + uuid, 200)
            return self.ratelimit.request(_)
        
        # Ban user by uuid (only admin and moderator)
        @app.route(self.get_uri("user/<uuid>/ban"), methods=["POST"])
        def banUser(uuid):
            def _():
                data = checkJson([[{"value": "reason", "type": str}]])
                if 'error' in data:
                    data = {"reason": "Unknown"}
                
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN, PERMISSIONS.MODERATOR]):
                    return error('unauthorized', 403)

                res = self.moderation.banUser(user['uuid'], uuid, data['reason'])
                if res: return error(res, 400)
                target['permissions'] = [PERMISSIONS.GUEST]
                self.update_user(user)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "ban_user", {
                        "by": user["uuid"],
                        "reason": data["reason"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "ban_user", {
                    "of": uuid,
                    "reason": data["reason"],
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.analytics.increment("banned_user_per_day")
                self.save_db()

                return result("User banned: " + uuid, 200)
            return self.ratelimit.request(_)
        
        # Unban user by uuid (only admin)
        @app.route(self.get_uri("user/<uuid>/unban"), methods=["POST"])
        def unbanUser(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)

                res = self.moderation.unbanUser(user['uuid'], uuid)
                if res: return error(res, 400)
                self.update_user(user)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "unban_user", {
                        "by": user["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "unban_user", {
                    "of": uuid,
                    "ip": request.remote_addr,
                })

                self.analytics.increment("actions_per_day")
                self.analytics.increment("unbanned_user_per_day")
                self.save_db()

                return result("User unbanned: " + uuid, 200)
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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if self.checkPermissions(user, target, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result(self.user_tree(user, self.getCredentials(user['uuid'])), 200)
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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if user != target and PERMISSIONS.ADMIN not in user["permissions"]:
                    return jsonify({"error": "Unauthorized"}), 403
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

                actions = self.get_actions(uuid)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "get_actions", {
                        "by": user["uuid"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "get_actions", {
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
                data = checkJson(
                    [[{"value": "action", "type": str}, {"value": "data", "type": dict}]])
                if 'error' in data:
                    return error(data['error'])

                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.getUserByUUID(uuid)
                if self.checkPermissions(user, target, [PERMISSIONS.ADMIN]):
                    return jsonify({"error": "Unauthorized"}), 403
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.data["users"][uuid]
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

                if data["permission"] in target["permissions"]:
                    return error('permission_already_exists', 400)

                target["permissions"].append(data["permission"])
                self.update_user(target)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "add_permission", {
                        "by": user["uuid"],
                        "permission": data["permission"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "add_permission", {
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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.data["users"][uuid]
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

                if data["permission"] not in target["permissions"]:
                    return error('permission_not_found', 404)

                if len(target["permissions"]) == 1:
                    return error('last_permission', 400)

                target["permissions"].remove(data["permission"])
                self.update_user(target)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "remove_permission", {
                        "by": user["uuid"],
                        "permission": data["permission"],
                        "ip": request.remote_addr,
                    })
                self.append_action(user["uuid"], "remove_permission", {
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

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                target = self.data["users"][uuid]
                if not self.checkPermissions(user, target, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(uuid):
                    return error('target_user_banned', 403)
                if self.moderation.isUserDeleted(uuid):
                    return error('target_user_deleted', 403)

                token_data = self.generate_credentials(uuid, data["password"])
                cred = self.data["credentials"][uuid]
                cred["password"] = token_data["password"]
                cred["token"] = token_data["token"]
                cred["salt"] = token_data["salt"]
                self.update_credentials(cred)

                if user['uuid'] != uuid:
                    self.append_action(uuid, "change_password", {
                        "by": user["uuid"],
                        "ip": request.remote_addr
                    })
                self.append_action(user["uuid"], "change_password", {
                    "of": uuid,
                    "ip": request.remote_addr
                })

                self.analytics.increment("actions_per_day")
                self.save_db()

                return result("Password changed", 200)
            return self.ratelimit.request(_)

        # Create demo account by uuid and name (only admin)
        @app.route(self.get_uri("demo"), methods=["POST"])
        def createDemo():
            def _():
                data = checkJson([[{"value": "uuid", "type": str}, {"value": "name", "type": str}]])
                if 'error' in data:
                    return error(data['error'])

                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                if not self.checkPermissions(user, user, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)
                
                if self.userExists(data['uuid']):
                    return error('user_already_exists', 400)
                
                target = self.register_user(data['uuid'], data['name'], True)
                self.data['users'][data['uuid']]['password'] = sha512(target['credentials']['password'].encode()).hexdigest()
                
                return result(target, 200)
            return self.ratelimit.request(_)
        
        # Delete demo account by uuid (only admin)
        @app.route(self.get_uri("demo/<uuid>"), methods=["DELETE"])
        def deleteDemo(uuid):
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)

                if not self.userExists(uuid):
                    return error('user_not_found', 404)

                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)

                if not self.checkPermissions(user, user, [PERMISSIONS.ADMIN], True):
                    return error('unauthorized', 403)
                
                target = self.data["users"][uuid]
                if not target["isDemo"]:
                    return error('not_a_demo', 400)

                self.remove_user(uuid)
                self.save_db()

                return result("Deleted demo user: " + uuid, 200)
            return self.ratelimit.request(_)
        
        # Get moderation (only admin)
        @app.route(self.get_uri("moderation"), methods=["GET"])
        def getModeration():
            def _():
                token = request.headers.get("Authorization")
                if not token:
                    return error('no_token_provided', 401)
                
                user = self.getUserByToken(token)
                if 'error' in user:
                    return error(user['error'], 401)
                
                if not self.checkPermissions(user, user, [PERMISSIONS.ADMIN]):
                    return error('unauthorized', 403)
                
                if self.moderation.isUserBanned(user['uuid']):
                    return error('user_banned', 403)
                if self.moderation.isUserDeleted(user['uuid']):
                    return error('user_deleted', 403)
                
                return result(self.moderation.actions, 200)
            return self.ratelimit.request(_)

        @app.route(self.get_uri(), methods=["GET", "POST", "PUT", "DELETE"])
        @app.route(self.get_uri("<first>"), methods=["GET", "POST", "PUT", "DELETE"])
        @app.route(self.get_uri("<first>/<path:rest>"), methods=["GET", "POST", "PUT", "DELETE"])
        def api(first="", rest=""):
            def _():
                return result("UwU Servers User API v1", 200)
            return self.ratelimit.request(_)

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
        return {"error": "invalid_token" }

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
            return {'error': 'name_mismatch' }
        return name

    def checkUUIDAndFetchName(self, uuid):
        response = requests.get(f"{self.check_uuid_uri}{uuid}")

        if response.status_code != 200:
            return {'error': 'uuid_not_found' }

        html = response.text
        site_name = re.search(
            r'results_username" class="w-full bg-gray-100 border border-gray-300 text-gray-900 p-2 rounded focusable" readonly="readonly" value="([a-zA-Z0-9_]+)"></td>', html)
        site_uuid = re.search(r'results_raw_id".+value="([a-f0-9-]+)', html)

        if (not site_uuid or site_uuid.group(1) != uuid) or not site_name:
            return {'error': 'uuid_not_found' }

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
        user["last_login_ip"] = request.remote_addr
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

    def register_user(self, uuid, name, isDemo=False):
        user = self.generate_user(uuid, name, isDemo)
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

    def generate_user(self, uuid, name, isDemo=False):
        return {
            "uuid": uuid,
            "name": name,
            "isDemo": isDemo,
            "created_timestamp": datetime.now().timestamp(),
            "last_login_timestamp": None,
            "last_login_ip": request.remote_addr,
            "registration_ip": request.remote_addr,
            "permissions": [
                PERMISSIONS.GUEST,
            ],
            "moderation": self.moderation.default(),
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
