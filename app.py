import logging
import requests
import asyncio
import time
import httpx
import json
from io import BytesIO
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cachetools import TTLCache
from PIL import Image, ImageDraw, ImageFont
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from flask_caching import Cache
from typing import Tuple, Optional
import my_pb2
import output_pb2
import requests
import binascii
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timezone
import random
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from protobuf_decoder.protobuf_decoder import Parser
from requests.exceptions import RequestException

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB49"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
TIMEOUT = httpx.Timeout(30.0, connect=60.0)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
def fetch_attversion():
    url = "https://raw.githubusercontent.com/minimalsend/release/refs/heads/main/version.json"  # Link com JSON simples

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        def buscar_attversion(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k == "attversion":
                        return v
                    resultado = buscar_attversion(v)
                    if resultado is not None:
                        return resultado
            elif isinstance(d, list):
                for item in d:
                    resultado = buscar_attversion(item)
                    if resultado is not None:
                        return resultado
            return None
        
        attversion = buscar_attversion(data)
        if attversion is not None:
            print(f"attversion: {attversion}")
            return attversion
        else:
            print("Parâmetro 'attversion' não encontrado.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
    except ValueError:
        print("Erro ao decodificar o JSON.")


# === Pre-downloaded assets ===

NIVEL_ICONES = {
    "admin": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL03.png",
    "vip": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL02.png",
    "user": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL01.png"
}

FONT_URL = "https://raw.githubusercontent.com/Thong-ihealth/arial-unicode/main/Arial-Unicode-Bold.ttf"

# Dicionário para armazenar os dados dos ícones baixados
ICONS_DATA = {}

for nivel, icon_url in NIVEL_ICONES.items():
    try:
        resp = requests.get(icon_url)
        resp.raise_for_status()
        ICONS_DATA[nivel] = resp.content
        logging.info("Ícone '%s' baixado com sucesso: %s", nivel, icon_url)
    except Exception as e:
        logging.error("Erro ao baixar ícone '%s' (%s): %s", nivel, icon_url, e)
        ICONS_DATA[nivel] = None
    try:
        resp = requests.get(FONT_URL)
        resp.raise_for_status()
        FONT_DATA = resp.content
        logging.info("Fonte personalizada baixada com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao baixar a fonte, usando padrão: {e}")
        FONT_DATA = None

# Exemplo: acessar os dados do ícone de celebrity
BADGE_DATA = ICONS_DATA.get("celebrity")
BADGE_DATA1 = ICONS_DATA.get("admin")
BADGE_DATA2 = ICONS_DATA.get("vip")

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.DEBUG)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
def is_uid_in_list(uid):
    url = "http://scvirtual.alphi.media/botsistem/sendlike/verified.json"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Erro ao carregar JSON: {e}")
        return False, None

    uid_str = str(uid)

    if uid_str in data:
        info = data[uid_str]
        if isinstance(info, dict):
            nivel = info.get("nivel", None)
            return True, nivel
        else:
            # UID está presente, mas não tem informação de nível
            return True, None
    else:
        return False, None



def get_custom_font(size):
    if FONT_DATA:
        try:
            return ImageFont.truetype(BytesIO(FONT_DATA), int(size))
        except Exception as e:
            logging.error("Error loading truetype from FONT_DATA: %s", e)
    return ImageFont.load_default()

def fetch_image(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return Image.open(BytesIO(resp.content)).convert("RGBA")
    except Exception as e:
        logging.error("Image fetch error from %s: %s", url, e)
        return None

def get_banner_url(banner_id):
    return f"https://raw.githubusercontent.com/minimalsend/RESOURCES_FF/refs/heads/main/BANNERS/{banner_id}.png"

def get_avatar_url(avatar_id):
    return f"https://raw.githubusercontent.com/minimalsend/RESOURCES_FF/refs/heads/main/AVATARS/{avatar_id}.png"

# Text positions & sizes
ACCOUNT_NAME_POSITION   = {"x": 62,  "y": 0,  "font_size": 12.5}
ACCOUNT_LEVEL_POSITION  = {"x": 180, "y": 45, "font_size": 12.5}
GUILD_NAME_POSITION     = {"x": 62,  "y": 40, "font_size": 12.5}
AVATAR_POSITION         = {"x": 0,   "y": 0,  "width": 60, "height": 60}
PIN_POSITION            = {"x": 0,   "y": 40, "width": 20, "height": 20}
BADGE_POSITION          = {"x": 35,  "y": -1,  "width": 28, "height": 28}

SCALE = 8
FALLBACK_BANNER_ID = "900000014"
FALLBACK_AVATAR_ID = "900000013"

# === Crypto & Protobuf Helpers ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_token(password: str, uid: str, max_retries: int = 3) -> Optional[dict]:
   
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    for attempt in range(max_retries):
        try:
            if attempt > 0:
                wait_time = min((2 ** attempt) + random.uniform(0, 1), 10)
                time.sleep(wait_time)

            res = requests.post(url, headers=headers, data=data, timeout=15)
            
            if res.status_code == 200:
                token_json = res.json()
                if "access_token" in token_json and "open_id" in token_json:
                    return token_json
            
            elif res.status_code == 429:
                retry_after = res.headers.get('Retry-After', 5)
                time.sleep(float(retry_after))
                continue
            
        except (RequestException, ValueError) as e:
            continue

    return None

def get_single_response() -> str:
    """Get authentication token."""
    uid = '3790435245'
    password = 'B8623E3106EDB07BD6D58B0D7688E5B7193854527368C9AF143984381BAFDBCE'
    versionob = fetch_attversion()
    token_data = get_token(password, uid)
    if not token_data:
        raise ValueError("Failed to get token: Wrong UID or Password")

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = aes_cbc_encrypt(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': f'{versionob}'
        }

        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=bytes.fromhex(edata),
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            response_dict = parse_response(str(example_msg))
            
            return response_dict.get("token")
        
        raise ValueError(f"HTTP {response.status_code} - {response.reason}")

    except Exception as e:
        raise ValueError(f"Token generation failed: {str(e)}")
def parse_response(content: str) -> dict:
    """Parse protobuf response into dictionary."""
    return dict(
        line.split(":", 1)
        for line in content.split("\n")
        if ":" in line
    )
def get_token():
    uid = "3790435245"
    password = "B8623E3106EDB07BD6D58B0D7688E5B7193854527368C9AF143984381BAFDBCE"
    
    url = "https://get-jwt.squareweb.app/get-token"
    params = {
        "uid": uid,
        "password": password
    }
    
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        return data.get("token")  # retorna apenas o token
    else:
        raise Exception(f"Erro ao obter token: {response.status_code}")
        
def GetAccountInformation(uid: str, unk: str, region: str, endpoint: str) -> dict:
    """Get player account information."""
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")

    try:
        # Monta o payload protobuf
        proto_message = main_pb2.GetPlayerPersonalShow()
        json_format.ParseDict({'a': uid, 'b': unk}, proto_message)
        payload = proto_message.SerializeToString()

        # Encripta com AES CBC
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        # Pega o token JWT e limpa possíveis aspas
        jwtlogin = get_single_response().strip().replace('"', '').replace("'", '')
        versionob = fetch_attversion()

        print(f"[DEBUG] JWT usado: {jwtlogin}")

        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': f'{versionob}',
            'Content-Type': 'application/octet-stream',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwtlogin}',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"

        with httpx.Client(timeout=TIMEOUT) as client:
            try:
                response = client.post(url, data=data_enc, headers=headers)
                response.raise_for_status()

                # Decodificar a resposta protobuf
                decoded_message = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                decoded_message.ParseFromString(response.content)

                # Converter para JSON legível
                json_data = json.loads(json_format.MessageToJson(decoded_message))

                return json_data

            except httpx.HTTPStatusError as http_err:
                print(f"[HTTP ERROR] Status: {http_err.response.status_code} - {http_err.response.text}")
                raise ValueError(f"HTTP Error {http_err.response.status_code}: {http_err.response.text}")

            except httpx.RequestError as req_err:
                print(f"[REQUEST ERROR] Request to {req_err.request.url} failed: {str(req_err)}")
                raise ValueError(f"Request error: {str(req_err)}")

            except Exception as e:
                print(f"[CLIENT ERROR] Unexpected error in HTTP client: {str(e)}")
                raise ValueError(f"Client error: {str(e)}")

    except Exception as e:
        print(f"[GENERAL ERROR] {str(e)}")
        raise ValueError(f"Failed to get account info: {str(e)}")

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

@app.route('/player-info')
def get_account_info():
    """Endpoint to get player information."""
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid or not region:
        return jsonify({"error": "UID and REGION are required"}), 400

    try:
        return_data = GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        return jsonify(return_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
