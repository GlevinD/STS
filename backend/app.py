from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
import hashlib
import datetime
import qrcode
import os
from pymongo import MongoClient
import secrets

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")

db = client["secure_ticketing"]
users_collection = db["users"]
tickets_collection = db["tickets"]

tickets = {}
app = Flask(__name__)

users = {}  # temporary in-memory storage


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")

    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    users_collection.insert_one({
        "username": username,
        "public_key": public_key.decode()
    })

    return jsonify({
        "message": "User registered successfully",
        "username": username,
        "private_key": private_key.decode()  # sent ONCE
    })


@app.route("/create-ticket", methods=["POST"])
def create_ticket():
    data = request.json
    username = data.get("username")
    event = data.get("event")

    if not username or not event:
        return jsonify({"error": "username and event required"}), 400

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    ticket_data = {
        "username": username,
        "event": event,
        "timestamp": str(datetime.datetime.utcnow())
    }

    public_key = RSA.import_key(user["public_key"])
    cipher = PKCS1_OAEP.new(public_key)

    encrypted_ticket = cipher.encrypt(
        json.dumps(ticket_data).encode()
    )

    ticket_hash = hashlib.sha256(encrypted_ticket).hexdigest()
    public_key_hash = hashlib.sha256(
        user["public_key"].encode()
    ).hexdigest()

    # Save ticket in MongoDB
    tickets_collection.insert_one({
        "ticket_hash": ticket_hash,
        "username": username,
        "public_key_hash": public_key_hash,
        "status": "unused"
    })

    # Generate QR
    if not os.path.exists("qrcodes"):
        os.makedirs("qrcodes")

    qr = qrcode.make(ticket_hash)
    qr_path = f"qrcodes/{ticket_hash}.png"
    qr.save(qr_path)

    return jsonify({
        "message": "Ticket created",
        "ticket_hash": ticket_hash,
        "qr_code": qr_path
    })


@app.route("/decrypt-ticket", methods=["POST"])
def decrypt_ticket():
    data = request.json
    encrypted_ticket_hex = data.get("encrypted_ticket")
    private_key_str = data.get("private_key")

    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)

    decrypted_data = cipher.decrypt(
        bytes.fromhex(encrypted_ticket_hex)
    )

    return jsonify({
        "ticket_data": json.loads(decrypted_data.decode())
    })


@app.route("/verify-ticket", methods=["POST"])
def verify_ticket():
    data = request.json
    ticket_hash = data.get("ticket_hash")

    ticket = tickets_collection.find_one({"ticket_hash": ticket_hash})
    if not ticket:
        return jsonify({"error": "Invalid ticket"}), 404

    if ticket["status"] == "used":
        return jsonify({"error": "Ticket already used"}), 400

    tickets_collection.update_one(
        {"ticket_hash": ticket_hash},
        {"$set": {"status": "used"}}
    )

    return jsonify({
        "message": "Ticket verified successfully",
        "status": "VALID"
    })


@app.route("/entry-challenge", methods=["POST"])
def entry_challenge():
    ticket_hash = request.json.get("ticket_hash")

    ticket = tickets_collection.find_one({"ticket_hash": ticket_hash})
    if not ticket:
        return jsonify({"error": "Invalid ticket"}), 404

    challenge = secrets.token_hex(16)

    tickets_collection.update_one(
        {"ticket_hash": ticket_hash},
        {"$set": {"challenge": challenge}}
    )

    return jsonify({"challenge": challenge})


@app.route("/verify-entry", methods=["POST"])
def verify_entry():
    data = request.json
    ticket_hash = data.get("ticket_hash")
    signature = bytes.fromhex(data.get("signature"))

    ticket = tickets_collection.find_one({"ticket_hash": ticket_hash})
    if not ticket or ticket["status"] == "used":
        return jsonify({"error": "Invalid or used ticket"}), 400

    user = users_collection.find_one({"username": ticket["username"]})
    public_key = RSA.import_key(user["public_key"])

    # ✅ Fixed: use pkcs1_15 for signature verification
    try:
        h = SHA256.new(ticket["challenge"].encode())
        pkcs1_15.new(public_key).verify(h, signature)

        tickets_collection.update_one(
            {"ticket_hash": ticket_hash},
            {"$set": {"status": "used"}}
        )
        return jsonify({"message": "ENTRY GRANTED"})
    except (ValueError, TypeError):
        return jsonify({"error": "Ownership verification failed"}), 403


@app.route("/")
def home():
    return jsonify({"message": "Secure Ticketing Backend Running"})


if __name__ == "__main__":
    app.run(debug=True)