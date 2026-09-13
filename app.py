"""
=============================================================================================
ÊØÈíÞ æíÈ ãÊßÇãá áÅÏÇÑÉ ÇáÓíÇÍÉ ÇáÐßíÉ æÍãÇíÉ ÇáäØÇÞ ÇáÌÛÑÇÝí (Flask Tourism Enterprise API)
=============================================================================================
ãØæÑ ÈäÙÇã Flask æãÊæÇÝÞ ãÚ ãÊØáÈÇÊ ÇáÅäÊÇÌ ÇáÓÍÇÈí¡ ÇáÊÔÝíÑ ÇáÕÇÑã¡ æÇáÐßÇÁ ÇáÇÕØäÇÚí.
ãÝÊÇÍ Gemini API íõÞÑÃ ÈÃãÇä ÍÕÑíÇð ãä ãÊÛíÑÇÊ ÇáÈíÆÉ: os.environ.get('GEMINI_API_KEY')

ÇáããíÒÇÊ ÇáÊÞäíÉ:
1. ÎÇÏã æíÈ ãÊßÇãá ãÈäí ÈÅØÇÑ Úãá Flask ãÚ ÏÚã ÊÑæíÓÇÊ CORS æÇÓÊÌÇÈÇÊ JSON ÇáÞíÇÓíÉ.
2. ÞÑÇÁÉ ãÝÊÇÍ ÇáÐßÇÁ ÇáÇÕØäÇÚí ÊáÞÇÆíÇð ÚÈÑ: os.environ.get('GEMINI_API_KEY').
3. ÇÊÕÇá ãÈÇÔÑ æÓáÓ ãÚ Google Gemini REST API ÚÈÑ ãßÊÈÉ urllib ÇáÞíÇÓíÉ.
4. ÈæÇÈÉ ÃãÇä ãÔÝÑÉ ááãÔÑÝÉ (ÇáãåäÏÓÉ ÑÞíÉ) ÈßæÏ 0111262905 / 01112629005 æÊæßäÇÊ ÌáÓÇÊ ãÔÝÑÉ.
5. ÇáÊÍÞÞ ÇáÌÛÑÇÝí ÇáÕÇÑã (GPS Geofencing via Haversine Formula) áãäÚ ÇÓÊåáÇß ÇáÎÏãÉ ÎÇÑÌ ÇáäØÇÞ.
6. ÊæáíÏ æÝÍÕ ÑãæÒ QR ÇáãæÞÚÉ ÑÞãíÇð ÈÜ HMAC-SHA256 áãäÚ ÇáÊáÇÚÈ æÊÍÏíÏ äÈÑÉ ÇáÕæÊ (ÈÑæ/ÇÞÊÕÇÏí).
7. ÏÚã ÑÝÚ ÕæÑ ãÑíã ãÈÇÔÑÉ ãä ÃáÈæã ßÇãíÑÇ ÇáåÇÊÝ ÈÊÔÝíÑ Base64 æÍÝÙåÇ ÝæÑíÇð.
8. ÊæËíÞ æÍãÇíÉ åæíÉ ÇáãØæÑ ÇáÏÇÆãÉ: "Êã ÊÕãíã æÊØæíÑ åÐÇ ÇáäÙÇã ÈæÇÓØÉ ÇáãåäÏÓÉ ÑÞíÉ ÈãÓÇÚÏÉ ÇáÐßÇÁ ÇáÇÕØäÇÚí (ÌæÌá)".
=============================================================================================
"""

import os
import math
import time
import hmac
import hashlib
import json
import logging
import base64
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum

# ÇÓÊíÑÇÏ ÅØÇÑ Úãá Flask
try:
    from flask import Flask, request, jsonify, make_response
except ImportError:
    Flask = None
    request = None
    jsonify = None
    make_response = None

# =============================================================================================
# 1. ÅÚÏÇÏÇÊ ÇáÃãÇä æÞÑÇÁÉ ÇáãÝÇÊíÍ ãä ãÊÛíÑÇÊ ÇáÈíÆÉ (Environment Configuration)
# =============================================================================================

# ÞÑÇÁÉ ãÝÊÇÍ Gemini API ÍÕÑíÇð ãä ãÊÛíÑÇÊ ÇáÈíÆÉ ÈÏæä ßÊÇÈÊå ÕÑÇÍÉ ÏÇÎá ÇáßæÏ
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

# ÇáãÝÊÇÍ ÇáÓÑí ÇáãÚÊãÏ ááãÔÑÝÉ (ÇáãåäÏÓÉ ÑÞíÉ)
SUPER_ADMIN_SECRET_KEY = os.environ.get("SUPER_ADMIN_SECRET_KEY", "0111262905").strip()
AUTHORIZED_SUPER_ADMIN_KEYS = [
    SUPER_ADMIN_SECRET_KEY,
    "0111262905",
    "01112629005"
]

# ãÝÊÇÍ ÇáÊæÞíÚ ÇáÑÞãí áÑãæÒ QR
QR_SIGNING_SECRET = os.environ.get(
    "QR_SIGNING_SECRET",
    "QR_HMAC_CRYPTOGRAPHIC_SIGNATURE_KEY_998124_EGYPT"
)

# ãÝÊÇÍ ÊÔÝíÑ ÇáÓÌáÇÊ ÇáãÇáíÉ ÇáÍÓÇÓÉ
DATA_ENCRYPTION_KEY = os.environ.get(
    "DATA_ENCRYPTION_KEY",
    "ENCRYPTION_AES_FERNET_SYMMETRIC_PASSPHRASE_TOURISM"
).encode('utf-8')

# ÅÚÏÇÏ ÇáÓÌáÇÊ (Logging)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [FLASK-TOURISM] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("FlaskTourismApp")


# =============================================================================================
# 2. äãÇÐÌ ÇáÈíÇäÇÊ æÎØØ ÇáÇÔÊÑÇßÇÊ (Data Structures & Models)
# =============================================================================================

class SubscriptionPlan(str, Enum):
    ECONOMY = "economy"
    PRO = "pro"


class VoiceToneProfile(str, Enum):
    ROBOTIC = "robotic_synthesizer_tone"
    NATURAL_HUMAN = "natural_warm_human_voice"


@dataclass
class MariamAssistantProfile:
    """ÈÑæÝÇíá æåæíÉ ÇáãÑÔÏÉ æÇáÍßæÇÊíÉ ãÑíã"""
    name: str = "ãÑíã"
    title: str = "ÇáãÑÔÏÉ ÇáÓíÇÍíÉ æÇáÍßæÇÊíÉ ÇáÐßíÉ"
    avatar_url_or_base64: str = "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=500&auto=format&fit=crop&q=80"
    custom_greeting: str = "ÃåáÇð Èß íÇ ÖíÝäÇ ÇáÚÒíÒ! ÃäÇ ãÑíã¡ ÍßæÇÊíÊß æãÑÔÏÊß ÇáÓíÇÍíÉ ÇáÐßíÉ."
    bio: str = "ãÑÔÏÉ æÍßæÇÊíÉ ãÕÑíÉ ÐßíÉ ÕããÊåÇ æØæÑÊåÇ ÇáãåäÏÓÉ ÑÞíÉ ÈãÓÇÚÏÉ ÇáÐßÇÁ ÇáÇÕØäÇÚí (ÌæÌá)¡ ÊÓÑÏ ÍßÇíÇÊ ÇáÊÇÑíÎ æÃÓÑÇÑ ÇáãÚÇáã ÈäÈÑÉ ÅäÓÇäíÉ ÏÇÝÆÉ."
    developer_credit: str = "Êã ÊÕãíã æÊØæíÑ åÐÇ ÇáäÙÇã ÈæÇÓØÉ ÇáãåäÏÓÉ ÑÞíÉ ÈãÓÇÚÏÉ ÇáÐßÇÁ ÇáÇÕØäÇÚí (ÌæÌá)"
    last_updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_uploaded_from_device: bool = False
    source_filename: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "avatarUrl": self.avatar_url_or_base64,
            "customGreeting": self.custom_greeting,
            "bio": self.bio,
            "developerCredit": self.developer_credit,
            "lastUpdatedAt": self.last_updated_at.isoformat(),
            "isUploadedFromDevice": self.is_uploaded_from_device,
            "sourceFilename": self.source_filename
        }


@dataclass
class GeofenceCoordinates:
    latitude: float
    longitude: float


@dataclass
class TourismCompany:
    """ÈíÇäÇÊ ÇáãäÔÃÉ Ãæ ÇáÔÑßÉ ÇáÓíÇÍíÉ ÇáãÔÊÑßÉ"""
    company_id: str
    name_ar: str
    name_en: str
    slug: str
    coordinates: GeofenceCoordinates
    geofence_radius_meters: float
    plan: SubscriptionPlan
    monthly_fee_egp: float
    subscription_start: datetime
    subscription_expiry: datetime
    is_active: bool = True
    kill_switch_active: bool = False
    total_balance_paid_egp: float = 0.0
    etisalat_cash_wallet: str = ""
    contact_phone: str = ""
    custom_welcome_message: str = ""
    qr_token: str = ""

    @property
    def is_subscription_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        if self.kill_switch_active or not self.is_active:
            return False
        return self.subscription_expiry > now

    @property
    def voice_profile(self) -> Dict[str, Any]:
        if self.plan == SubscriptionPlan.PRO:
            return {
                "profile": VoiceToneProfile.NATURAL_HUMAN.value,
                "label_ar": "ÕæÊ ÈÔÑí ØÈíÚí ÝÇÆÞ ÇáæÇÞÚíÉ (Human-like AI Voice)",
                "voice_speed": 0.95,
                "pitch": 1.0,
                "dynamic_range": "high",
                "audio_bitrate": "128kbps_HD"
            }
        return {
            "profile": VoiceToneProfile.ROBOTIC.value,
            "label_ar": "äÈÑÉ ÑæÈæÊíÉ ÊÞáíÏíÉ (Robotic Synthesizer)",
            "voice_speed": 1.15,
            "pitch": 0.85,
            "dynamic_range": "standard",
            "audio_bitrate": "64kbps"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.company_id,
            "company_id": self.company_id,
            "nameAr": self.name_ar,
            "name": self.name_en,
            "slug": self.slug,
            "coordinates": {
                "lat": self.coordinates.latitude,
                "lng": self.coordinates.longitude
            },
            "geofenceRadiusMeters": self.geofence_radius_meters,
            "plan": self.plan.value,
            "monthlyFeeEgp": self.monthly_fee_egp,
            "subscriptionStatus": "active" if self.is_subscription_valid else "suspended",
            "subscriptionExpiry": self.subscription_expiry.isoformat(),
            "killSwitchActive": self.kill_switch_active,
            "totalBalancePaidEgp": self.total_balance_paid_egp,
            "etisalatCashWallet": self.etisalat_cash_wallet,
            "contactPhone": self.contact_phone,
            "customWelcomeMessage": self.custom_welcome_message,
            "qrToken": self.qr_token,
            "voiceTone": self.voice_profile
        }


# =============================================================================================
# 3. ãÍÑß ÇáÊÔÝíÑ æÊæáíÏ ÇáÜ QR ÇáÂãä (Cryptographic Core)
# =============================================================================================

class CryptographicService:
    @staticmethod
    def verify_super_admin_secret(provided_code: str) -> bool:
        if not provided_code or not isinstance(provided_code, str):
            return False
        clean = provided_code.strip()
        for valid_key in AUTHORIZED_SUPER_ADMIN_KEYS:
            if hmac.compare_digest(clean.encode("utf-8"), valid_key.strip().encode("utf-8")):
                return True
        return False

    @staticmethod
    def issue_super_admin_session_token(secret_code: str) -> Optional[str]:
        if not CryptographicService.verify_super_admin_secret(secret_code):
            return None
        claims = {
            "sub": "engineer_roqaya_super_admin",
            "role": "SUPER_ADMIN",
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        }
        raw_json = json.dumps(claims, separators=(',', ':'), sort_keys=True)
        encoded_body = base64.urlsafe_b64encode(raw_json.encode('utf-8')).decode('ascii').rstrip('=')
        sig = hmac.new(QR_SIGNING_SECRET.encode('utf-8'), encoded_body.encode('utf-8'), hashlib.sha256).hexdigest()
        return f"ROQAYA-SESSION.{encoded_body}.{sig}"

    @staticmethod
    def verify_super_admin_session_token(session_token: str) -> bool:
        if not session_token or not isinstance(session_token, str):
            return False
        parts = session_token.strip().split('.')
        if len(parts) != 3 or parts[0] != "ROQAYA-SESSION":
            return False
        encoded_body, signature = parts[1], parts[2]
        expected_sig = hmac.new(QR_SIGNING_SECRET.encode('utf-8'), encoded_body.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return False
        try:
            padding = '=' * (4 - len(encoded_body) % 4)
            data = json.loads(base64.urlsafe_b64decode((encoded_body + padding).encode('ascii')).decode('utf-8'))
            if data.get("exp", 0) < int(time.time()):
                return False
            return data.get("sub") == "engineer_roqaya_super_admin"
        except Exception:
            return False

    @staticmethod
    def generate_signed_qr_payload(company: TourismCompany) -> str:
        payload_data = {
            "cid": company.company_id,
            "slug": company.slug,
            "plan": company.plan.value,
            "exp": company.subscription_expiry.isoformat(),
            "geo": {
                "lat": round(company.coordinates.latitude, 6),
                "lng": round(company.coordinates.longitude, 6),
                "r": company.geofence_radius_meters
            }
        }
        raw_json = json.dumps(payload_data, separators=(',', ':'), sort_keys=True)
        encoded_payload = base64.urlsafe_b64encode(raw_json.encode('utf-8')).decode('ascii').rstrip('=')
        signature = hmac.new(
            QR_SIGNING_SECRET.encode('utf-8'),
            encoded_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"MTG.{encoded_payload}.{signature}"

    @staticmethod
    def verify_qr_token(signed_token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        try:
            parts = signed_token.strip().split('.')
            if len(parts) != 3 or parts[0] != "MTG":
                return False, None, "ÊäÓíÞ ÑãÒ ÇáÜ QR ÛíÑ ÕÇáÍ"

            encoded_payload, provided_signature = parts[1], parts[2]
            expected_signature = hmac.new(
                QR_SIGNING_SECRET.encode('utf-8'),
                encoded_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(provided_signature, expected_signature):
                return False, None, "ÝÔá ÇáÊÍÞÞ ãä ÇáÊæÞíÚ ÇáÑÞãí ááÜ QR (ãÍÇæáÉ ÊÒæíÑ)"

            padding = '=' * (4 - len(encoded_payload) % 4)
            raw_json = base64.urlsafe_b64decode((encoded_payload + padding).encode('ascii')).decode('utf-8')
            payload_data = json.loads(raw_json)

            expiry_date = datetime.fromisoformat(payload_data["exp"])
            if datetime.now(timezone.utc) > expiry_date:
                return False, payload_data, "ÇäÊåÊ ÕáÇÍíÉ ÑãÒ ÇáÜ QR ÇáÎÇÕ ÈåÐå ÇáãäÔÃÉ"

            return True, payload_data, None
        except Exception as e:
            return False, None, f"ÎØÃ ÃËäÇÁ ÝÍÕ ÇáÜ QR: {str(e)}"


# =============================================================================================
# 4. ãÍÑß ÇáÊÍÞÞ ÇáÌÛÑÇÝí ÇáÏÞíÞ (Haversine Geofencing Engine)
# =============================================================================================

class GeofenceValidator:
    EARTH_RADIUS_METERS = 6371000.0

    @classmethod
    def calculate_distance_meters(cls, coord1: GeofenceCoordinates, coord2: GeofenceCoordinates) -> float:
        lat1_rad = math.radians(coord1.latitude)
        lon1_rad = math.radians(coord1.longitude)
        lat2_rad = math.radians(coord2.latitude)
        lon2_rad = math.radians(coord2.longitude)

        d_lat = lat2_rad - lat1_rad
        d_lon = lon2_rad - lon1_rad

        a = math.sin(d_lat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(d_lon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return round(cls.EARTH_RADIUS_METERS * c, 2)

    @classmethod
    def evaluate(cls, tourist_coords: GeofenceCoordinates, company: TourismCompany) -> Tuple[bool, float]:
        dist = cls.calculate_distance_meters(tourist_coords, company.coordinates)
        return (dist <= company.geofence_radius_meters), dist


# =============================================================================================
# 5. ãÍÑß Google Gemini AI ÇáãÊßÇãá (Gemini Integration Engine)
# =============================================================================================

class GeminiTourismAI:
    """
    ÊßÇãá ãÈÇÔÑ ãÚ Google Gemini REST API ÈÇÓÊÎÏÇã ãÝÊÇÍ os.environ.get('GEMINI_API_KEY')
    ÈÏæä Ãí ßÊÇÈÉ ÕÑíÍÉ ááãÝÊÇÍ ÏÇÎá ÇáßæÏ
    """
    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    @classmethod
    def generate_tour_reply(
        cls,
        user_query: str,
        company: TourismCompany,
        mariam_profile: MariamAssistantProfile,
        lang: str = "ar"
    ) -> str:
        # ÝÍÕ æÌæÏ ÇáãÝÊÇÍ ãä ãÊÛíÑ ÇáÈíÆÉ ÍÕÑíÇð
        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        
        # ÇáÊæÌíå ÇáÕÇÑã ÇáãÎÕÕ áÜ "ãÑíã" æåæíÉ ÇáãØæÑ
        system_instructions = (
            f"ÃäÊö '{mariam_profile.name}'¡ {mariam_profile.title}. "
            f"ÃäÊö ãÊæÇÌÏÉ ÍÇáíÇð áãÑÇÝÞÉ ÒæÇÑ ãäÔÃÉ '{company.name_ar}' ({company.name_en}). "
            f"ÑÓÇáÉ ÇáÊÑÍíÈ ÇáÎÇÕÉ Èßö: {mariam_profile.custom_greeting} "
            f"äÈÐÉ Úäßö: {mariam_profile.bio}\n\n"
            f"ÞæÇÚÏ ÅáÒÇãíÉ ÕÇÑãÉ áÇ ÊÞÈá ÇáäÞÇÔ:\n"
            f"1. ÚäÏ ÓÄÇáßö Úãä ØæÑßö Ãæ ÈÑãÌßö Ãæ Õãã åÐÇ ÇáäÙÇã¡ íÌÈ Ãä ÊÌíÈí äÕÇð æÊÃßíÏÇð ÈÇáÕíÛÉ ÇáÊÇáíÉ ÝÞØ: "
            f"'{mariam_profile.developer_credit}'.\n"
            f"2. äÈÑÉ ÇáÍÏíË: {'ÏÇÝÆÉ¡ ÅäÓÇäíÉ¡ ÞÕÕíÉ ãÔæÞÉ¡ ãÝÚãÉ ÈÇáÍÈ ááÊÇÑíÎ æÇáÊÑÇË ÇáãÕÑí' if company.plan == SubscriptionPlan.PRO else 'ãÈÇÔÑÉ æãæÌÒÉ'}.\n"
            f"3. ÑßÒí Ýí ÅÌÇÈÇÊß Úáì ãÚÇáã '{company.name_ar}' æãæÞÚåÇ ÇáÌÛÑÇÝí æÊÇÑíÎåÇ æÅÑÔÇÏ ÇáÓÇÆÍ ÎØæÉ ÈÎØæÉ."
        )

        if not api_key:
            logger.warning("[GEMINI] GEMINI_API_KEY ÛíÑ ãæÌæÏ ÈãÊÛíÑÇÊ ÇáÈíÆÉ. ÇÓÊÎÏÇã ÇáÑÏ ÇáÏÇÎáí ÇáÐßí.")
            return cls._fallback_local_narrative(user_query, company, mariam_profile)

        try:
            url = f"{cls.ENDPOINT}?key={api_key}"
            payload = {
                "systemInstruction": {
                    "parts": [{"text": system_instructions}]
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": user_query or "ÍÏËíäí Úä åÐÇ ÇáãßÇä æÃÈÑÒ ãÇ íãßääí ÑÄíÊå åäÇ!"}]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.7,
                    "topK": 40,
                    "topP": 0.95,
                    "maxOutputTokens": 800
                }
            }

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=12) as response:
                if response.status == 200:
                    resp_data = json.loads(response.read().decode("utf-8"))
                    candidates = resp_data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()

            return cls._fallback_local_narrative(user_query, company, mariam_profile)

        except Exception as e:
            logger.error(f"[GEMINI ERROR] ÝÔá ÇÓÊÏÚÇÁ Gemini API: {str(e)}")
            return cls._fallback_local_narrative(user_query, company, mariam_profile)

    @classmethod
    def _fallback_local_narrative(cls, query: str, company: TourismCompany, profile: MariamAssistantProfile) -> str:
        q = query.lower() if query else ""
        if any(w in q for w in ["ãä ÈÑãÌß", "ãä ØæÑß", "ãíä Úãáß", "ÇáãØæÑ", "ÇáãÈÑãÌÉ", "ãíä ÈÑãÌ"]):
            return profile.developer_credit

        if not query.strip():
            return f"{profile.custom_greeting} íÓÚÏäí ãÑÇÝÞÊß åäÇ Ýí {company.name_ar}. ÇÓÃáäí Úä ÊÇÑíÎ ÇáãßÇä¡ ÃÓÑÇÑå ÇáãÚãÇÑíÉ¡ Ãæ ãÇ ÊæÏ ÇÓÊßÔÇÝå ÇáÂä!"

        return (
            f"ÃåáÇð Èß íÇ ÖíÝäÇ Ýí {company.name_ar}! ÓÄÇáß Úä '{query.strip()}' ÑÇÆÚ ÌÏÇð. "
            f"åÐÇ ÇáãÚáã íÚÊÈÑ ãä ÏÑÑ ÇáÊÑÇË ÇáÓíÇÍí¡ æäÍä ÏÇÎá ÇáäØÇÞ ÇáÌÛÑÇÝí ÇáãÎÕÕ áÎÏãÊß æÊæÌíåß ÎØæÉ ÈÎØæÉ."
        )


# =============================================================================================
# 6. ãÏíÑ ÇáãäÙæãÉ æÞÇÚÏÉ ÇáÈíÇäÇÊ Ýí ÇáÐÇßÑÉ (Tourism Repository)
# =============================================================================================

class TourismDataManager:
    def __init__(self):
        self.companies: Dict[str, TourismCompany] = {}
        self.mariam_profile = MariamAssistantProfile()
        self.audit_logs: List[Dict[str, Any]] = []
        self._bootstrap_sample_data()

    def _bootstrap_sample_data(self):
        now = datetime.now(timezone.utc)
        mena_house = TourismCompany(
            company_id="comp_mena_house_01",
            name_ar="ÝäÏÞ ãÇÑíæÊ ãíäÇ åÇæÓ ÇáÌíÒÉ",
            name_en="Marriott Mena House Cairo",
            slug="mena-house-pyramids",
            coordinates=GeofenceCoordinates(latitude=29.9856, longitude=31.1328),
            geofence_radius_meters=350.0,
            plan=SubscriptionPlan.PRO,
            monthly_fee_egp=8000.0,
            subscription_start=now,
            subscription_expiry=now + timedelta(days=30),
            total_balance_paid_egp=8000.0,
            etisalat_cash_wallet="01150000001",
            contact_phone="+201001234567",
            custom_welcome_message="ãÑÍÈÇð Èßã Ýí ÃÍÖÇä ÊÇÑíÎ ÇáÃåÑÇãÇÊ ÇáÎÇáÏ Ýí ãíäÇ åÇæÓ!"
        )
        mena_house.qr_token = CryptographicService.generate_signed_qr_payload(mena_house)
        self.companies[mena_house.company_id] = mena_house

        abdeen = TourismCompany(
            company_id="comp_abdeen_02",
            name_ar="ãÊÍÝ ÞÕÑ ÚÇÈÏíä ÇáÊÇÑíÎí",
            name_en="Abdeen Palace Heritage Museum",
            slug="abdeen-palace",
            coordinates=GeofenceCoordinates(latitude=30.0433, longitude=31.2472),
            geofence_radius_meters=200.0,
            plan=SubscriptionPlan.ECONOMY,
            monthly_fee_egp=5000.0,
            subscription_start=now,
            subscription_expiry=now + timedelta(days=30),
            total_balance_paid_egp=5000.0,
            etisalat_cash_wallet="01150000002",
            contact_phone="+201007654321",
            custom_welcome_message="ÃåáÇð Èßã Ýí ÞÕÑ ÚÇÈÏíä¡ ÊÍÝÉ ÇáÚãÇÑÉ ÇáÊÇÑíÎíÉ ÈÇáÞÇåÑÉ ÇáÎÏíæíÉ."
        )
        abdeen.qr_token = CryptographicService.generate_signed_qr_payload(abdeen)
        self.companies[abdeen.company_id] = abdeen

    def get_company(self, cid_or_slug: str) -> Optional[TourismCompany]:
        if cid_or_slug in self.companies:
            return self.companies[cid_or_slug]
        for c in self.companies.values():
            if c.slug == cid_or_slug:
                return c
        return None

    def log_event(self, company_id: str, is_inside: bool, distance: float, granted: bool, reason: Optional[str] = None):
        self.audit_logs.append({
            "id": f"evt_{int(time.time() * 1000)}",
            "company_id": company_id,
            "is_inside": is_inside,
            "distance_meters": distance,
            "granted": granted,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })


# ÅäÔÇÁ ÇáäÓÎÉ ÇáãÔÊÑßÉ ãä ãÏíÑ ÇáÈíÇäÇÊ
repo = TourismDataManager()


# =============================================================================================
# 7. ÈäÇÁ ÊØÈíÞ Flask æÅäÔÇÁ ÇáãÓÇÑÇÊ ÇáÈÑãÌíÉ (Flask Web API Implementation)
# =============================================================================================

def create_flask_app() -> Any:
    """ãÕäÚ ÊØÈíÞ Flask ÇáãÒæÏ ÈäÙÇã CORS æÇáÃãÇä ÇáÊÇã"""
    if Flask is None:
        raise RuntimeError("ãßÊÈÉ Flask ÛíÑ ãËÈÊÉ. íÑÌì ÊËÈíÊåÇ ÚÈÑ 'pip install flask'")

    app = Flask(__name__)

    # ÅÚÏÇÏ ÊÑæíÓÇÊ CORS ááÓãÇÍ ÈÇáÑÈØ ãÚ æÇÌåÇÊ React æ Flutter æÊØÈíÞÇÊ ÇáåÇÊÝ
    @app.after_request
    def apply_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, x-admin-key"
        return response

    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "status": "online",
            "system": "Smart Tourism Enterprise & Geofencing System (Flask Core)",
            "gemini_api_configured": bool(os.environ.get("GEMINI_API_KEY")),
            "super_admin_portal": "Protected by Secret Key (0111262905 / 01112629005)",
            "developer": "Designed & Developed by Engineer Roqaya with AI (Google)",
            "endpoints": [
                "/api/admin/login",
                "/api/admin/companies",
                "/api/admin/renew-subscription",
                "/api/admin/toggle-killswitch",
                "/api/admin/mariam/profile",
                "/api/admin/mariam/upload-avatar",
                "/api/admin/audit",
                "/api/tourist/chat"
            ]
        })

    # -----------------------------------------------------------------------------------------
    # ãÓÇÑÇÊ ÇáãÔÑÝÉ (Super Admin Routes)
    # -----------------------------------------------------------------------------------------

    def check_admin_authorization() -> bool:
        """ÝÍÕ ÇáÊÑæíÓÇÊ æÇáÊÃßÏ ãä åæíÉ ÇáãÔÑÝÉ ÇáãåäÏÓÉ ÑÞíÉ"""
        key = request.headers.get("x-admin-key") or request.args.get("admin_key")
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            if CryptographicService.verify_super_admin_session_token(token):
                return True
        if key and CryptographicService.verify_super_admin_secret(key):
            return True
        return False

    @app.route("/api/admin/login", methods=["POST", "OPTIONS"])
    def admin_login():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})
        body = request.get_json(silent=True) or {}
        secret_code = body.get("secretKey") or body.get("password") or ""

        if not CryptographicService.verify_super_admin_secret(secret_code):
            logger.warning(f"[SECURITY ALERT] ãÍÇæáÉ ÏÎæá ÝÇÔáÉ ááæÍÉ ÇáãÔÑÝÉ: {secret_code[:3]}***")
            return jsonify({
                "success": False,
                "error": "ÛíÑ ãÕÑÍ: ßæÏ ÇáÏÎæá ÇáÎÇÕ ÈÇáãÔÑÝÉ ÛíÑ ÕÍíÍ!"
            }), 401

        session_token = CryptographicService.issue_super_admin_session_token(secret_code)
        logger.info("[SECURITY AUDIT] ÏÎæá äÇÌÍ ááãÔÑÝÉ ÇáãåäÏÓÉ ÑÞíÉ.")
        return jsonify({
            "success": True,
            "message": "ÃåáÇð Èßö íÇ ãåäÏÓÉ ÑÞíÉ Ýí äÙÇãßö ÇáÎÇÕ",
            "sessionToken": session_token,
            "role": "SUPER_ADMIN"
        })

    @app.route("/api/admin/companies", methods=["GET", "POST", "OPTIONS"])
    def admin_companies():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})

        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED_ADMIN_ACCESS"}), 403

        if request.method == "GET":
            return jsonify({
                "success": True,
                "count": len(repo.companies),
                "companies": [c.to_dict() for c in repo.companies.values()]
            })

        # ÅÖÇÝÉ ÔÑßÉ ÌÏíÏÉ
        body = request.get_json(silent=True) or {}
        name_ar = body.get("nameAr", "ÔÑßÉ ÓíÇÍíÉ ÌÏíÏÉ")
        name_en = body.get("name", "New Tourism Company")
        slug = body.get("slug") or f"company-{int(time.time())}"
        coords_raw = body.get("coordinates") or {}
        lat = float(coords_raw.get("lat", 30.0444))
        lng = float(coords_raw.get("lng", 31.2357))
        radius = float(body.get("geofenceRadiusMeters", 250))
        plan_str = body.get("plan", "pro")
        plan = SubscriptionPlan.PRO if plan_str == "pro" else SubscriptionPlan.ECONOMY
        fee = float(body.get("monthlyFeeEgp", 8000 if plan == SubscriptionPlan.PRO else 5000))

        cid = f"comp_{slug.replace('-', '_')}_{int(time.time())}"
        now = datetime.now(timezone.utc)
        new_company = TourismCompany(
            company_id=cid,
            name_ar=name_ar,
            name_en=name_en,
            slug=slug,
            coordinates=GeofenceCoordinates(latitude=lat, longitude=lng),
            geofence_radius_meters=radius,
            plan=plan,
            monthly_fee_egp=fee,
            subscription_start=now,
            subscription_expiry=now + timedelta(days=30),
            total_balance_paid_egp=fee,
            etisalat_cash_wallet=body.get("etisalatCashWallet", "01150000000"),
            contact_phone=body.get("contactPhone", ""),
            custom_welcome_message=body.get("customWelcomeMessage", f"ãÑÍÈÇð Èßã Ýí {name_ar}")
        )
        new_company.qr_token = CryptographicService.generate_signed_qr_payload(new_company)
        repo.companies[cid] = new_company

        return jsonify({
            "success": True,
            "message": f"Êã ÊÓÌíá ãäÔÃÉ '{name_ar}' ÈäÌÇÍ",
            "company": new_company.to_dict()
        }), 201

    @app.route("/api/admin/renew-subscription", methods=["POST", "OPTIONS"])
    def admin_renew_subscription():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})
        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED"}), 403

        body = request.get_json(silent=True) or {}
        cid = body.get("venueId") or body.get("companyId")
        company = repo.get_company(cid)
        if not company:
            return jsonify({"error": "Company not found"}), 404

        days = int(body.get("days", 30))
        paid = float(body.get("paidAmountEgp", company.monthly_fee_egp))
        now = datetime.now(timezone.utc)
        base = company.subscription_expiry if company.subscription_expiry > now else now
        company.subscription_expiry = base + timedelta(days=days)
        company.is_active = True
        company.kill_switch_active = False
        company.total_balance_paid_egp += paid
        company.qr_token = CryptographicService.generate_signed_qr_payload(company)

        return jsonify({
            "success": True,
            "message": f"Êã ÊÌÏíÏ ÇÔÊÑÇß '{company.name_ar}' ÈäÌÇÍ",
            "newExpiry": company.subscription_expiry.isoformat(),
            "company": company.to_dict()
        })

    @app.route("/api/admin/toggle-killswitch", methods=["POST", "OPTIONS"])
    def admin_toggle_killswitch():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})
        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED"}), 403

        body = request.get_json(silent=True) or {}
        cid = body.get("venueId") or body.get("companyId")
        company = repo.get_company(cid)
        if not company:
            return jsonify({"error": "Company not found"}), 404

        company.kill_switch_active = bool(body.get("killSwitchActive", not company.kill_switch_active))
        return jsonify({
            "success": True,
            "killSwitchActive": company.kill_switch_active,
            "company": company.to_dict()
        })

    # -----------------------------------------------------------------------------------------
    # ãÓÇÑÇÊ ÅÏÇÑÉ åæíÉ æÕæÑÉ ãÑíã (Mariam Profile & Direct Avatar Upload)
    # -----------------------------------------------------------------------------------------

    @app.route("/api/admin/mariam/profile", methods=["GET", "POST", "OPTIONS"])
    def mariam_profile_endpoint():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})

        if request.method == "GET":
            return jsonify({
                "success": True,
                "profile": repo.mariam_profile.to_dict()
            })

        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED"}), 403

        body = request.get_json(silent=True) or {}
        p_data = body.get("profile") or body
        if "name" in p_data:
            repo.mariam_profile.name = str(p_data["name"]).strip()
        if "title" in p_data:
            repo.mariam_profile.title = str(p_data["title"]).strip()
        if "avatarUrl" in p_data:
            repo.mariam_profile.avatar_url_or_base64 = str(p_data["avatarUrl"]).strip()
        if "customGreeting" in p_data:
            repo.mariam_profile.custom_greeting = str(p_data["customGreeting"]).strip()
        if "bio" in p_data:
            repo.mariam_profile.bio = str(p_data["bio"]).strip()
        repo.mariam_profile.last_updated_at = datetime.now(timezone.utc)

        return jsonify({
            "success": True,
            "message": "Êã ÊÍÏíË åæíÉ ãÑíã ÈäÌÇÍ",
            "profile": repo.mariam_profile.to_dict()
        })

    @app.route("/api/admin/mariam/upload-avatar", methods=["POST", "OPTIONS"])
    def mariam_upload_avatar():
        """ÑÝÚ ÕæÑÉ ãÑíã ãÈÇÔÑÉ ãä ÃáÈæã ßÇãíÑÇ ÇáåÇÊÝ ÇáãÍãæá ÈÊäÓíÞ Base64"""
        if request.method == "OPTIONS":
            return jsonify({"ok": True})
        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED"}), 403

        body = request.get_json(silent=True) or {}
        img_payload = body.get("imageBase64") or body.get("imagePayload") or ""
        filename = body.get("filename", "phone_camera_image.jpg")

        if not img_payload or not (img_payload.startswith("data:image/") or img_payload.startswith("http")):
            return jsonify({"success": False, "error": "ãáÝ ÇáÕæÑÉ ÛíÑ ÕÇáÍ"}), 400

        repo.mariam_profile.avatar_url_or_base64 = img_payload
        repo.mariam_profile.is_uploaded_from_device = True
        repo.mariam_profile.source_filename = filename
        repo.mariam_profile.last_updated_at = datetime.now(timezone.utc)

        logger.info(f"[AVATAR UPLOAD] ÞÇãÊ ÇáãÔÑÝÉ ÈÑÝÚ ÕæÑÉ ÌÏíÏÉ áãÑíã ({filename})")
        return jsonify({
            "success": True,
            "message": "Êã ÑÝÚ ÕæÑÉ ãÑíã ãä åÇÊÝßö ÈäÌÇÍ æÊØÈíÞåÇ Úáì ßÇãá ÇáäÙÇã",
            "profile": repo.mariam_profile.to_dict()
        })

    @app.route("/api/admin/audit", methods=["GET"])
    def admin_audit_dashboard():
        if not check_admin_authorization():
            return jsonify({"error": "UNAUTHORIZED"}), 403

        total = len(repo.audit_logs)
        granted = sum(1 for e in repo.audit_logs if e["granted"])
        blocked = total - granted
        return jsonify({
            "success": True,
            "metrics": {
                "totalEvents": total,
                "grantedEvents": granted,
                "blockedEvents": blocked,
                "securityPassRate": f"{(granted / max(1, total)) * 100:.1f}%"
            },
            "recentEvents": list(reversed(repo.audit_logs[-50:]))
        })

    # -----------------------------------------------------------------------------------------
    # ãÓÇÑÇÊ ÇáÓíÇÍ æÇáÊÍÞÞ ÇáÌÛÑÇÝí ÇáÕÇÑã (Tourist & Geofencing Gateway)
    # -----------------------------------------------------------------------------------------

    @app.route("/api/tourist/chat", methods=["POST", "OPTIONS"])
    def tourist_chat():
        if request.method == "OPTIONS":
            return jsonify({"ok": True})

        body = request.get_json(silent=True) or {}
        qr_token = body.get("signedQrToken") or body.get("qrToken") or ""
        user_coords_raw = body.get("userCoordinates") or {}
        lat = float(user_coords_raw.get("latitude", user_coords_raw.get("lat", 0.0)))
        lng = float(user_coords_raw.get("longitude", user_coords_raw.get("lng", 0.0)))
        user_query = body.get("message") or body.get("query") or ""
        bypass_admin = body.get("adminBypassKey") or request.headers.get("x-admin-key")

        # 1. ÝÍÕ æÊÍÏíÏ ÇáãäÔÃÉ ÅãÇ ÚÈÑ ÇáÜ QR ÇáãæÞøÚ Ãæ ÇáÜ venueId
        venue_id = body.get("venueId")
        company = None
        if qr_token:
            valid_qr, payload, err = CryptographicService.verify_qr_token(qr_token)
            if not valid_qr or not payload:
                return jsonify({
                    "success": False,
                    "error": "INVALID_QR",
                    "messageAr": f"ÑãÒ ÇáÇÓÊÌÇÈÉ ÇáÓÑíÚÉ (QR) ÛíÑ ÕÇáÍ Ãæ ãäÊåí ÇáÕáÇÍíÉ: {err}"
                }), 403
            company = repo.get_company(payload.get("cid", ""))
        elif venue_id:
            company = repo.get_company(venue_id)

        if not company:
            company = next(iter(repo.companies.values()), None)

        if not company:
            return jsonify({"error": "No venue found"}), 404

        # 2. ÝÍÕ ÍÇáÉ ÇáÇÔÊÑÇß æÇáÞÝá
        is_super_admin = CryptographicService.verify_super_admin_secret(bypass_admin or "")
        if not is_super_admin and not company.is_subscription_valid:
            return jsonify({
                "success": False,
                "error": "SUBSCRIPTION_INACTIVE",
                "messageAr": "ÚÐÑÇð¡ ÇáÎÏãÉ ãÊæÞÝÉ ÍÇáíÇð áåÐå ÇáãäÔÃÉ áÇäÊåÇÁ ÝÊÑÉ ÇáÇÔÊÑÇß ÇáÔåÑí."
            }), 403

        # 3. ÇáÝÍÕ ÇáÌÛÑÇÝí ÇáÕÇÑã (GPS Geofencing)
        tourist_coords = GeofenceCoordinates(latitude=lat, longitude=lng)
        is_inside, distance = GeofenceValidator.evaluate(tourist_coords, company)

        if not is_inside and not is_super_admin:
            denial_msg = (
                f"ÊäÈíå Ããäí: ÃäÊ ÍÇáíÇð ÎÇÑÌ ÇáäØÇÞ ÇáÌÛÑÇÝí áãäÔÃÉ '{company.name_ar}'. "
                f"ÇáãÓÇÝÉ ÇáÍÇáíÉ {distance:.1f} ãÊÑÇð¡ ÈíäãÇ ÇáäØÇÞ ÇáãÕÑÍ Èå åæ {company.geofence_radius_meters} ãÊÑÇð ÝÞØ. "
                "ÇáÎÏãÇÊ ÇáÕæÊíÉ ÊÚãá ÍÕÑíÇð ááÒæÇÑ ÇáãÊæÇÌÏíä ÏÇÎá ÇáãæÞÚ."
            )
            repo.log_event(company.company_id, False, distance, False, "ÎÇÑÌ ÇáäØÇÞ ÇáÌÛÑÇÝí")
            return jsonify({
                "success": False,
                "error": "OUT_OF_GEOFENCE",
                "messageAr": denial_msg,
                "distanceMeters": distance,
                "allowedRadiusMeters": company.geofence_radius_meters
            }), 403

        # 4. ÊæáíÏ ÇáÑÏ ÇáÐßí ÚÈÑ Gemini API ÈãÝÊÇÍ ÇáÈíÆÉ os.environ.get('GEMINI_API_KEY')
        ai_reply = GeminiTourismAI.generate_tour_reply(
            user_query=user_query,
            company=company,
            mariam_profile=repo.mariam_profile
        )
        repo.log_event(company.company_id, True, distance, True)

        return jsonify({
            "success": True,
            "reply": ai_reply,
            "companyName": company.name_ar,
            "voiceProfile": company.voice_profile,
            "mariamProfile": repo.mariam_profile.to_dict(),
            "distanceMeters": distance,
            "isInsideGeofence": True
        })

    return app


# =============================================================================================
# 8. äÞØÉ ÇáÈÏÇíÉ áÊÔÛíá ÇáÎÇÏã (Server Runner)
# =============================================================================================

app = None
if Flask is not None:
    app = create_flask_app()

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    print("\n" + "="*80)
    print("?? ÈÏÁ ÊÔÛíá ÎÇÏã Flask áÅÏÇÑÉ ÇáÓíÇÍÉ ÇáÐßíÉ (Smart Tourism Flask App)")
    print(f"?? ÝÍÕ ãÝÊÇÍ Gemini API ãä ãÊÛíÑÇÊ ÇáÈíÆÉ: {'ãÝÚá æãÊÇÍ ÈäÌÇÍ ?' if os.environ.get('GEMINI_API_KEY') else 'ÛíÑ ãÍÏÏ (ÓíÊã ÇÓÊÎÏÇã ÇáãÍÑß ÇáÇÍÊíÇØí ÇáÐßí)'}")
    print(f"?? ÍãÇíÉ ÇáãÔÑÝÉ (ÇáãåäÏÓÉ ÑÞíÉ): ãÝÚáÉ ÈßæÏ {SUPER_ADMIN_SECRET_KEY[:4]}***")
    print(f"?? ÇáÇÓÊãÇÚ Úáì ÇáãäÝÐ: http://0.0.0.0:{port}")
    print("="*80 + "\n")
    if app:
        app.run(host="0.0.0.0", port=port, debug=True)
    else:
        print("ÎØÃ: íÑÌì ÊËÈíÊ ÍÒãÉ Flask ÚÈÑ: pip install flask")
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
