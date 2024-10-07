from flask import request, jsonify


class Violations:
    def __init__(self, api):
        self.api_data = api.data
        self.violations_data = api.data["violations"]
        self.app = api.app
        self.get_uri = api.get_uri
        self.append_action = api.append_action
        self.getUserByToken = api.getUserByToken
        self.ratelimit = api.ratelimit
        self.increment_analytics = api.increment_analytics
        self.decrement_analytics = api.decrement_analytics
        self.save_db = api.save_db
        
        @self.app.route(self.get_uri("user/<uuid>/violations"), methods=["GET"])
        def violations(uuid):
            ip = request.remote_addr
            if not self.ratelimit.check_ip(ip):
                return result({"error": "Rate limit exceeded"}, 429)

            token = request.headers.get("Authorization")

            if not token:
                return jsonify({"error": "No token provided"}), 401

            if uuid not in self.data["users"]:
                return jsonify({"error": "User not found"}), 404

            uuidUser = self.data["users"][uuid]
            tokenUser = self.getUserByToken(token)

            if not tokenUser:
                return jsonify({"error": "Invalid token"}), 401

            if tokenUser != uuidUser and PERMISSIONS.ADMIN not in tokenUser["permissions"]:
                return jsonify({"error": "Unauthorized"}), 403
            
            

            if tokenUser != uuidUser:
                self.append_action(uuidUser["uuid"], "get_violations", {
                    "by": tokenUser["uuid"],
                    "ip": ip,
                })
            self.append_action(tokenUser["uuid"], "get_violations", {
                "of": uuidUser["uuid"],
                "ip": ip,
            })

            self.increment_analytics("actions_per_day")
            self.increment_analytics("delete_user_per_day")
            self.save_db()

            return jsonify({"message": "User deleted: " + uuid}), 200