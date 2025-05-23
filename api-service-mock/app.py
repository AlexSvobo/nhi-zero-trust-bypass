from flask import Flask, jsonify, request
import jwt
import time

app = Flask(__name__)

# For JWT verification (should be a strong, separate secret in production)
JWT_SECRET = "your_super_secret_jwt_key_for_testing" # This is the key that might be "leaked" if used as an NHI

@app.route('/v1/secrets', methods=['GET'])
def get_restricted_secrets():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"message": "Authorization header missing or malformed"}), 401

    token = auth_header.split(' ')[1]

    try:
        # In a real system, you'd fetch the public key/certificate to verify
        # For this PoC, we'll verify with a hardcoded secret if the stolen NHI is a JWT signing key.
        # Or, if the stolen NHI is just an API key, you'd check against a list of valid keys.
        if token == "STATIC_BREAK_GLASS_KEY_XYZABC": # Direct API key check (updated for demo)
            return jsonify({"sensitive_data": "Access granted with static API key!", "policy": "Bypassed"}), 200
        
        # Attempt JWT decoding if it looks like a JWT
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if decoded_token.get("role") == "admin":
            return jsonify({"sensitive_data": "Access granted with forged JWT!", "user_info": decoded_token}), 200
        else:
            return jsonify({"message": "Invalid JWT role"}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        print(f"Error during token validation: {e}")
        return jsonify({"message": "Internal server error during validation"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "up"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
