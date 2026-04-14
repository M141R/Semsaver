from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlparse
from uuid import uuid4
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from supabase import Client, create_client

try:
    from azure.core.exceptions import ResourceExistsError
    from azure.storage.blob import (
        BlobSasPermissions,
        BlobServiceClient,
        ContentSettings,
        generate_blob_sas,
    )
except Exception:  # pragma: no cover
    ResourceExistsError = Exception
    BlobServiceClient = None
    ContentSettings = None
    BlobSasPermissions = None
    generate_blob_sas = None

load_dotenv()

url: str | None = os.environ.get("SUPABASE_URL")
key: str | None = os.environ.get("SUPABASE_KEY")
supabase: Client | None = None
if url and key:
    supabase = create_client(url, key)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

is_production = os.environ.get("FLASK_ENV", "development").lower() == "production"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = is_production
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

if is_production and app.secret_key == "dev-key-change-me":
    raise RuntimeError("SECRET_KEY must be set in production.")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

login_manager = LoginManager(app)
login_manager.login_view = "admin_login"
login_manager.login_message = "Please log in to access admin pages."
login_manager.login_message_category = "error"

ADMIN_ID = "admin"
RESOURCE_TYPES = {"Note", "Syllabus", "Paper"}
AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
AZURE_STORAGE_ACCOUNT_NAME = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME", "")
AZURE_STORAGE_ACCOUNT_KEY = os.environ.get(
    "AZURE_STORAGE_ACCOUNT_KEY", os.environ.get("AZURE_STORAGE_KEY", "")
)
AZURE_STORAGE_CONTAINER = os.environ.get("AZURE_STORAGE_CONTAINER", "resources")
TYPE_TO_STORAGE_FOLDER = {
    "Note": "notes",
    "Syllabus": "syllabus",
    "Paper": "papers",
}


def create_blob_service_client():
    if not BlobServiceClient:
        return None

    if AZURE_STORAGE_CONNECTION_STRING:
        return BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

    if AZURE_STORAGE_ACCOUNT_NAME and AZURE_STORAGE_ACCOUNT_KEY:
        account_url = f"https://{AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
        return BlobServiceClient(
            account_url=account_url, credential=AZURE_STORAGE_ACCOUNT_KEY
        )

    return None


blob_service_client = create_blob_service_client()


class AdminUser(UserMixin):
    def __init__(self, user_id: str):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id: str):
    if user_id == ADMIN_ID:
        return AdminUser(ADMIN_ID)
    return None


@login_manager.unauthorized_handler
def handle_unauthorized():
    flash("Please log in to access admin pages.", "error")
    return redirect(url_for("admin_login"))


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_or_abort():
    expected = session.get("_csrf_token", "")
    provided = request.form.get("csrf_token", "")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        abort(400, description="Invalid CSRF token.")


@app.context_processor
def inject_template_globals():
    return {"csrf_token": get_csrf_token}


@app.before_request
def configure_session_policy():
    session.permanent = True


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    return response


def fetch_resources(select_columns: str = "*"):
    if not supabase:
        return []

    response = (
        supabase.table("resources")
        .select(select_columns)
        .order("created_at", desc=True)
        .execute()
    )
    return response.data or []


def build_stats(resources):
    return {
        "total": len(resources),
        "notes": len([r for r in resources if (r.get("type") or "").lower() == "note"]),
        "syllabi": len(
            [r for r in resources if (r.get("type") or "").lower() == "syllabus"]
        ),
        "papers": len(
            [r for r in resources if (r.get("type") or "").lower() == "paper"]
        ),
    }


def parse_tags(raw_tags: str):
    cleaned = [tag.strip() for tag in raw_tags.split(",") if tag.strip()]
    return cleaned[:15]


def upload_pdf_and_get_public_url(
    uploaded_file, semester_value: int, resource_type: str
):
    if not blob_service_client:
        raise ValueError(
            "Azure Blob Storage is not configured. Set AZURE_STORAGE_* environment variables."
        )

    file_name = secure_filename(uploaded_file.filename or "")
    if not file_name:
        raise ValueError("Please select a valid PDF file.")

    if not file_name.lower().endswith(".pdf"):
        raise ValueError("Only PDF uploads are allowed.")

    file_bytes = uploaded_file.read()
    if not file_bytes:
        raise ValueError("Uploaded file is empty.")

    folder = TYPE_TO_STORAGE_FOLDER.get(resource_type, "notes")
    blob_path = f"{folder}/semester-{semester_value}/{uuid4().hex}_{file_name}"
    blob_client = blob_service_client.get_blob_client(
        container=AZURE_STORAGE_CONTAINER,
        blob=blob_path,
    )

    content_settings = (
        ContentSettings(content_type="application/pdf") if ContentSettings else None
    )

    try:
        blob_client.upload_blob(
            file_bytes,
            overwrite=False,
            content_settings=content_settings,
        )
    except ResourceExistsError as exc:
        raise ValueError("File already exists, please retry upload.") from exc

    return blob_client.url


def maybe_extract_blob_path(file_url: str):
    parsed = urlparse(file_url or "")
    if not parsed.netloc or ".blob.core.windows.net" not in parsed.netloc:
        return None

    path = parsed.path.lstrip("/")
    container_prefix = f"{AZURE_STORAGE_CONTAINER}/"
    if not path.startswith(container_prefix):
        return None

    return unquote(path[len(container_prefix) :])


def is_azure_blob_url(file_url: str):
    parsed = urlparse(file_url or "")
    return ".blob.core.windows.net" in parsed.netloc


def build_signed_blob_url(file_url: str, expires_in_minutes: int = 30):
    if not file_url or not is_azure_blob_url(file_url):
        return file_url

    blob_path = maybe_extract_blob_path(file_url)
    if not blob_path:
        return file_url

    if not AZURE_STORAGE_ACCOUNT_NAME or not AZURE_STORAGE_ACCOUNT_KEY:
        return file_url

    if not generate_blob_sas or not BlobSasPermissions:
        return file_url

    token = generate_blob_sas(
        account_name=AZURE_STORAGE_ACCOUNT_NAME,
        container_name=AZURE_STORAGE_CONTAINER,
        blob_name=blob_path,
        account_key=AZURE_STORAGE_ACCOUNT_KEY,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
    )
    if not token:
        return file_url

    return f"{file_url.split('?', 1)[0]}?{token}"


def with_resolved_file_urls(resources):
    resolved = []
    for resource in resources:
        item = dict(resource)
        item["file_url"] = build_signed_blob_url(item.get("file_url") or "")
        resolved.append(item)
    return resolved


def filter_resources(
    resources, q: str, subject: str, resource_type: str, semester: str
):
    filtered = resources

    if subject:
        filtered = [r for r in filtered if (r.get("subject") or "") == subject]

    if resource_type:
        filtered = [r for r in filtered if (r.get("type") or "") == resource_type]

    if semester:
        filtered = [r for r in filtered if str(r.get("semester") or "") == semester]

    if q:
        query = q.lower()

        def matches(resource):
            tags = resource.get("tags") or []
            tags_text = " ".join(tags) if isinstance(tags, list) else str(tags)
            haystack = " ".join(
                [
                    str(resource.get("title") or ""),
                    str(resource.get("subject") or ""),
                    str(resource.get("type") or ""),
                    tags_text,
                ]
            ).lower()
            return query in haystack

        filtered = [r for r in filtered if matches(r)]

    return filtered


def require_supabase_or_redirect():
    if supabase:
        return False
    flash("Supabase is not configured. Check SUPABASE_URL and SUPABASE_KEY.", "error")
    return True


def require_blob_storage_or_redirect():
    if blob_service_client:
        return False
    flash(
        "Azure Blob Storage is not configured. Check AZURE_STORAGE_* environment variables.",
        "error",
    )
    return True


@app.route("/")
def hello():
    resources = fetch_resources(
        "id,title,type,subject,semester,file_url,tags,created_at"
    )

    q = (request.args.get("q") or "").strip()
    subject = (request.args.get("subject") or "").strip()
    resource_type = (request.args.get("type") or "").strip()
    semester = (request.args.get("semester") or "").strip()

    if resource_type and resource_type not in RESOURCE_TYPES:
        resource_type = ""

    filtered = filter_resources(resources, q, subject, resource_type, semester)
    filtered = with_resolved_file_urls(filtered)

    subjects = sorted({r.get("subject") for r in resources if r.get("subject")})
    semesters = sorted({str(r.get("semester")) for r in resources if r.get("semester")})

    return render_template(
        "index.html",
        data=filtered,
        subjects=subjects,
        semesters=semesters,
        filter_values={
            "q": q,
            "subject": subject,
            "type": resource_type,
            "semester": semester,
        },
        title="SemSaver Library | Repository",
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))

    error = None
    if request.method == "POST":
        validate_csrf_or_abort()

        submitted = request.form.get("password", "")
        admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")

        if not admin_password_hash:
            error = "ADMIN_PASSWORD_HASH is not configured."
            return render_template(
                "admin/login.html", title="SemSaver Admin | Login", error=error
            )

        if (
            submitted
            and admin_password_hash
            and check_password_hash(admin_password_hash, submitted)
        ):
            login_user(AdminUser(ADMIN_ID))
            return redirect(url_for("admin"))

        error = "Invalid password. Please try again."

    return render_template(
        "admin/login.html", title="SemSaver Admin | Login", error=error
    )


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    validate_csrf_or_abort()
    logout_user()
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if request.method == "POST":
        validate_csrf_or_abort()

        if require_supabase_or_redirect():
            return redirect(url_for("admin"))

        title = (request.form.get("title") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        resource_type = (request.form.get("type") or "").strip()
        semester_raw = (request.form.get("semester") or "").strip()
        tags_raw = (request.form.get("tags") or "").strip()
        file_url = (request.form.get("file_url") or "").strip()
        upload_file = request.files.get("resource_file")

        if not title or not subject or not resource_type or not semester_raw:
            flash("Title, subject, type, and semester are required.", "error")
            return redirect(url_for("admin"))

        if len(title) > 180 or len(subject) > 100:
            flash("Title or subject is too long.", "error")
            return redirect(url_for("admin"))

        if resource_type not in RESOURCE_TYPES:
            flash("Type must be one of: Note, Syllabus, or Paper.", "error")
            return redirect(url_for("admin"))

        try:
            semester = int(semester_raw)
        except ValueError:
            flash("Semester must be a number.", "error")
            return redirect(url_for("admin"))

        if semester < 1 or semester > 12:
            flash("Semester must be between 1 and 12.", "error")
            return redirect(url_for("admin"))

        has_upload = bool(upload_file and upload_file.filename)
        has_url = bool(file_url)
        if has_upload == has_url:
            flash(
                "Provide either a PDF upload or an external file URL (exactly one).",
                "error",
            )
            return redirect(url_for("admin"))

        if has_url and not file_url.lower().startswith(("http://", "https://")):
            flash("External file URL must start with http:// or https://.", "error")
            return redirect(url_for("admin"))

        if has_upload and require_blob_storage_or_redirect():
            return redirect(url_for("admin"))

        try:
            final_file_url = (
                upload_pdf_and_get_public_url(upload_file, semester, resource_type)
                if has_upload
                else file_url
            )
        except Exception as exc:
            flash(f"Upload failed: {exc}", "error")
            return redirect(url_for("admin"))

        payload = {
            "title": title,
            "type": resource_type,
            "subject": subject,
            "semester": semester,
            "file_url": final_file_url,
            "tags": parse_tags(tags_raw),
        }

        try:
            supabase.table("resources").insert(payload).execute()
        except Exception as exc:
            flash(f"Database insert failed: {exc}", "error")
            return redirect(url_for("admin"))

        flash("Resource saved successfully.", "success")
        return redirect(url_for("admin"))

    resources = fetch_resources(
        "id,title,type,subject,semester,file_url,tags,created_at"
    )
    resolved_resources = with_resolved_file_urls(resources)
    stats = build_stats(resources)
    return render_template(
        "admin/dashboard.html",
        title="SemSaver Admin | Dashboard",
        recent_resources=resolved_resources[:6],
        resources=resolved_resources,
        stats=stats,
    )


@app.route("/admin/resources/<int:resource_id>/delete", methods=["POST"])
@login_required
def delete_resource(resource_id: int):
    validate_csrf_or_abort()

    if require_supabase_or_redirect():
        return redirect(url_for("admin"))

    file_url = None
    try:
        lookup = (
            supabase.table("resources")
            .select("file_url")
            .eq("id", resource_id)
            .limit(1)
            .execute()
        )
        if lookup.data:
            file_url = lookup.data[0].get("file_url")
    except Exception:
        file_url = None

    try:
        supabase.table("resources").delete().eq("id", resource_id).execute()
    except Exception as exc:
        flash(f"Delete failed: {exc}", "error")
        return redirect(url_for("admin"))

    blob_path = maybe_extract_blob_path(file_url or "")
    if blob_path and blob_service_client:
        try:
            blob_client = blob_service_client.get_blob_client(
                container=AZURE_STORAGE_CONTAINER,
                blob=blob_path,
            )
            blob_client.delete_blob(delete_snapshots="include")
        except Exception:
            pass

    flash("Resource deleted successfully.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(400)
def bad_request(_err):
    return "Bad request.", 400


@app.errorhandler(413)
def file_too_large(_err):
    flash("Upload too large. Max allowed size is 50MB.", "error")
    if current_user.is_authenticated:
        return redirect(url_for("admin")), 413
    return redirect(url_for("admin_login")), 413


@app.errorhandler(500)
def server_error(_err):
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
