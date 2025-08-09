from flask import Flask, request, jsonify
import base64
import json
import logging
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import time
import os
from threading import Thread
import schedule

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ملفات التكوين
CONFIG_FILE = "me_config.json"
TOKEN_FILE = "token_ME.json"
TOKEN_REFRESH_INTERVAL = 5 * 60 * 60  # 5 ساعات بالثواني

class TokenManager:
    def __init__(self):
        self.tokens = []
        self.last_refresh_time = 0
        self.load_tokens()

    def load_tokens(self):
        """تحميل التوكنات من الملف"""
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'r') as f:
                    self.tokens = json.load(f)
                    self._extract_uids()
                    logging.info(f"تم تحميل {len(self.tokens)} توكن من الملف")
            else:
                self.refresh_tokens()
        except Exception as e:
            logging.error(f"خطأ في تحميل التوكنات: {e}")
            self.tokens = []

    def _extract_uids(self):
        """استخراج UID من التوكنات"""
        for t in self.tokens:
            if "uid" not in t or not t["uid"]:
                try:
                    payload_part = t["token"].split(".")[1]
                    padded_payload = payload_part + "=" * (-len(payload_part) % 4)
                    payload_json = json.loads(base64.urlsafe_b64decode(padded_payload).decode())
                    t["uid"] = str(payload_json.get("external_uid", ""))
                except Exception as e:
                    logging.error(f"خطأ في استخراج UID من التوكن: {e}")
                    t["uid"] = ""

    def get_tokens(self):
        # فقط ترجع التوكنات الحالية بدون أي تجديد
        return self.tokens

    def refresh_tokens(self):
        """تجديد جميع التوكنات من حسابات me_config.json"""
        try:
            if not os.path.exists(CONFIG_FILE):
                logging.error(f"ملف التكوين {CONFIG_FILE} غير موجود")
                return False
            
            with open(CONFIG_FILE, 'r') as f:
                accounts = json.load(f)
            
            new_tokens = []
            for account in accounts:
                token = self.get_new_token(account['uid'], account['password'])
                if token:
                    new_tokens.append({
                        "token": token,
                        "uid": account['uid']
                    })
            
            if new_tokens:
                self.tokens = new_tokens
                self._extract_uids()
                self._save_tokens()
                self.last_refresh_time = time.time()
                logging.info(f"تم تجديد {len(new_tokens)} توكن بنجاح")
                return True
            return False
        except Exception as e:
            logging.error(f"خطأ في تجديد التوكنات: {e}")
            return False
    
    def get_new_token(self, uid, password):
        """استخراج توكن جديد لـ UID معين"""
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            else:
                logging.error(f"فشل في الحصول على توكن لـ {uid}: {response.text}")
                return None
        except Exception as e:
            logging.error(f"خطأ في طلب التوكن لـ {uid}: {e}")
            return None
    
    def _save_tokens(self):
        """حفظ التوكنات في الملف"""
        try:
            with open(TOKEN_FILE, 'w') as f:
                json.dump(self.tokens, f, indent=2)
            logging.info(f"تم حفظ التوكنات في {TOKEN_FILE}")
        except Exception as e:
            logging.error(f"خطأ في حفظ التوكنات: {e}")

# تهيئة مدير التوكنات
token_manager = TokenManager()

# باقي الدوال كما هي (مع تعديل بسيط لاستخدام token_manager بدلاً من TokenCache)
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = token_manager.get_tokens()
        if not tokens:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "ME":
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            tokens = token_manager.get_tokens()
            if not tokens:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # بيانات اللاعب قبل الإعجاب
            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            # رابط الإعجاب حسب السيرفر
            if server_name == "ME":
                url = "https://clientbp.ggblueshark.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # إرسال لايكات بشكل غير متزامن
            asyncio.run(send_multiple_requests(uid, server_name, url))

            # بيانات اللاعب بعد الإعجاب
            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

def run_scheduler():
    """تشغيل المجدول لتجديد التوكنات كل 5 ساعات"""
    schedule.every(TOKEN_REFRESH_INTERVAL).seconds.do(token_manager.refresh_tokens)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    # بدء خيط منفصل للمجدول
    scheduler_thread = Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    app.run(debug=True, use_reloader=False)