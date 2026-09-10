from io import BytesIO

from PIL import Image
from pyzbar.pyzbar import decode as decode_qr

from app.utils.url_checker import check_url
from app.utils.payment_checker import check_payment, UPI_PATTERN


def check_qr(contents: bytes):
    """
    Decodes a QR code image and routes the embedded content through the
    URL checker or payment checker depending on what it contains.
    """
    reasons = []
    features = {
        "decoded": False,
        "content_type": "unknown",
    }

    try:
        image = Image.open(BytesIO(contents))
        decoded = decode_qr(image)
    except Exception:
        return {
            "risk": "Low",
            "score": 0,
            "reasons": ["Could not open image file"],
            "features": features,
            "decoded_content": None,
        }

    if not decoded:
        return {
            "risk": "Low",
            "score": 0,
            "reasons": ["No QR code found in the image"],
            "features": features,
            "decoded_content": None,
        }

    payload = decoded[0].data.decode("utf-8", errors="replace")
    features["decoded"] = True

    if payload.startswith("http://") or payload.startswith("https://"):
        features["content_type"] = "url"
        result = check_url(payload)
        reasons.append(f"QR code links to: {payload}")
        reasons.extend(result["reasons"])
        return {
            "risk": result["risk"],
            "score": result["score"],
            "reasons": reasons,
            "features": {**features, "url_features": result["features"]},
            "decoded_content": payload,
        }

    if payload.startswith("upi://") or UPI_PATTERN.match(payload):
        features["content_type"] = "payment"
        # UPI deep links look like upi://pay?pa=handle@bank&...
        upi_id = payload
        if payload.startswith("upi://"):
            import urllib.parse
            params = urllib.parse.parse_qs(urllib.parse.urlparse(payload).query)
            upi_id = params.get("pa", [payload])[0]
        result = check_payment(upi_id)
        reasons.append(f"QR code is a payment request to: {upi_id}")
        reasons.extend(result["reasons"])
        return {
            "risk": result["risk"],
            "score": result["score"],
            "reasons": reasons,
            "features": {**features, "payment_features": result["features"]},
            "decoded_content": payload,
        }

    features["content_type"] = "text"
    reasons.append("QR code contains plain text, not a URL or payment request")
    return {
        "risk": "Low",
        "score": 0,
        "reasons": reasons,
        "features": features,
        "decoded_content": payload,
    }
