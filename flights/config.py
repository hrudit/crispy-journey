"""fligths development configuration."""

import pathlib

# Root of this application, useful if it doesn't occupy an entire domain
APPLICATION_ROOT = '/'

# Secret key for encrypting cookies
SECRET_KEY = b't\xf9\x80\xdb\xd8\xf3\xbc@(<\xa2k8\x81\xa4\x90\xa4iAC\xaa\xfaV\x83'
SESSION_COOKIE_NAME = 'login'
VERIFICATION_SID = 'VAf34b851708349a2bbad21dda720eb3c5'
# File Upload to var/uploads/
INSTA485_ROOT = pathlib.Path(__file__).resolve().parent.parent
UPLOAD_FOLDER = INSTA485_ROOT/'var'/'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
TWILIO_ACCOUNT_SID = 'ACedb4f830e6afdfc70bfcf5850f757a1e'
TWILIO_AUTH_TOKEN = '0d30851f21d515edfb16a501328dc34c'
TWILIO_PHONE_NUMBER = '+18329816613'
# Database file is var/insta485.sqlite3
DATABASE_FILENAME = INSTA485_ROOT/'var'/'insta485.sqlite3'