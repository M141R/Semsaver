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
db_key: str | None = os.environ.get("SUPABASE_KEY")
auth_key: str | None = os.environ.get("SUPABASE_ANON_KEY") or db_key
supabase: Client | None = None
supabase_auth: Client | None = None
if url and db_key:
    supabase = create_client(url, db_key)
if url and auth_key:
    supabase_auth = create_client(url, auth_key)

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
login_manager.login_view = "auth_login"
login_manager.login_message = "Please log in to access admin pages."
login_manager.login_message_category = "error"

APP_NAME = "BITVault"
RESOURCE_TYPES = {"Note", "Syllabus", "Paper"}
MODERATOR_ROLES = {"moderator", "admin"}
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
PUBLIC_UPLOAD_MAX_MB = int(os.environ.get("PUBLIC_UPLOAD_MAX_MB", "10"))
PUBLIC_UPLOAD_MAX_BYTES = PUBLIC_UPLOAD_MAX_MB * 1024 * 1024


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


class AppUser(UserMixin):
    def __init__(self, user_id: str, role: str):
        self.id = user_id
        self.role = role


def get_user_role(user_id: str):
    if not supabase:
        return None
    try:
        response = (
            supabase.table("user_roles")
            .select("role")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if response.data:
            return response.data[0].get("role")
    except Exception:
        return None
    return None


@login_manager.user_loader
def load_user(user_id: str):
    role = get_user_role(user_id)
    if role:
        return AppUser(user_id, role)
    return None


@login_manager.unauthorized_handler
def handle_unauthorized():
    flash("Please log in to access admin pages.", "error")
    return redirect(url_for("auth_login"))


def current_role():
    if current_user.is_authenticated:
        return getattr(current_user, "role", None)
    return None


def role_in(*allowed_roles):
    return current_user.is_authenticated and current_role() in allowed_roles


def require_role_or_redirect(*allowed_roles):
    if role_in(*allowed_roles):
        return False
    flash("You do not have permission to access this page.", "error")
    return True


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
    return {
        "csrf_token": get_csrf_token,
        "public_upload_max_mb": PUBLIC_UPLOAD_MAX_MB,
        "current_role": current_role,
    }


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
    try:
        response = (
            supabase.table("resources")
            .select(select_columns)
            .order("created_at", desc=True)
            .execute()
        )
        return response.data or []
    except Exception as exc:
        app.logger.error("Supabase fetch_resources failed: %s", exc)
        return []


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


def fetch_submissions(status: str | None = None, limit: int | None = None):
    if not supabase:
        return []
    try:
        query = supabase.table("resource_submissions").select(
            "id,title,type,subject,semester,file_url,tags,status,review_note,reviewed_at,submitted_by,created_at"
        )
        if status:
            query = query.eq("status", status)
        else:
            query = query.neq("status", "pending")
        query = query.order("created_at", desc=True)
        if limit:
            query = query.limit(limit)

        response = query.execute()
        data = response.data or []
        return with_resolved_file_urls(data)
    except Exception as exc:
        app.logger.error("Supabase fetch_submissions failed: %s", exc)
        return []


def get_submission_by_id(submission_id: int):
    if not supabase:
        return None
    try:
        response = (
            supabase.table("resource_submissions")
            .select("*")
            .eq("id", submission_id)
            .limit(1)
            .execute()
        )
        if response.data:
            return response.data[0]
    except Exception as exc:
        app.logger.error("Supabase get_submission_by_id failed: %s", exc)
    return None


def create_submission(payload):
    if not supabase:
        raise ValueError("Supabase is not configured.")
    supabase.table("resource_submissions").insert(payload).execute()


def update_submission(submission_id: int, payload):
    if not supabase:
        raise ValueError("Supabase is not configured.")
    supabase.table("resource_submissions").update(payload).eq(
        "id", submission_id
    ).execute()


def validate_size_limit(upload_file, limit_bytes: int):
    current = upload_file.stream.tell()
    upload_file.stream.seek(0, os.SEEK_END)
    size = upload_file.stream.tell()
    upload_file.stream.seek(current)
    if size > limit_bytes:
        raise ValueError(f"File exceeds {limit_bytes // (1024 * 1024)}MB limit.")


def parse_resource_form(form, files):
    title = (form.get("title") or "").strip()
    subject = (form.get("subject") or "").strip()
    resource_type = (form.get("type") or "").strip()
    semester_raw = (form.get("semester") or "").strip()
    tags_raw = (form.get("tags") or "").strip()
    file_url = (form.get("file_url") or "").strip()
    upload_file = files.get("resource_file")

    if not title or not subject or not resource_type or not semester_raw:
        raise ValueError("Title, subject, type, and semester are required.")

    if len(title) > 180 or len(subject) > 100:
        raise ValueError("Title or subject is too long.")

    if resource_type not in RESOURCE_TYPES:
        raise ValueError("Type must be one of: Note, Syllabus, or Paper.")

    try:
        semester = int(semester_raw)
    except ValueError as exc:
        raise ValueError("Semester must be a number.") from exc

    if semester < 1 or semester > 12:
        raise ValueError("Semester must be between 1 and 12.")

    has_upload = bool(upload_file and upload_file.filename)
    has_url = bool(file_url)
    if has_upload == has_url:
        raise ValueError(
            "Provide either a PDF upload or an external file URL (exactly one)."
        )

    if has_url and not file_url.lower().startswith(("http://", "https://")):
        raise ValueError("External file URL must start with http:// or https://.")

    return {
        "title": title,
        "subject": subject,
        "resource_type": resource_type,
        "semester": semester,
        "tags": parse_tags(tags_raw),
        "file_url": file_url,
        "upload_file": upload_file,
        "has_upload": has_upload,
        "has_url": has_url,
    }


def has_duplicate_resource(title: str, subject: str, semester: int):
    resources = fetch_resources("title,subject,semester")
    normalized = title.strip().lower()
    for item in resources:
        if (
            (item.get("title") or "").strip().lower() == normalized
            and (item.get("subject") or "") == subject
            and int(item.get("semester") or 0) == semester
        ):
            return True
    return False


def delete_blob_if_needed(file_url: str):
    blob_path = maybe_extract_blob_path(file_url or "")
    if not blob_path or not blob_service_client:
        return
    try:
        blob_client = blob_service_client.get_blob_client(
            container=AZURE_STORAGE_CONTAINER,
            blob=blob_path,
        )
        blob_client.delete_blob(delete_snapshots="include")
    except Exception:
        pass


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


def fetch_resource_by_id(resource_id: int):
    if not supabase:
        return None
    response = (
        supabase.table("resources")
        .select("id,title,type,subject,semester,file_url,tags,created_at")
        .eq("id", resource_id)
        .limit(1)
        .execute()
    )
    if not response.data:
        return None
    resource = with_resolved_file_urls(response.data)[0]
    return resource


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


def require_auth_client_or_redirect(endpoint: str):
    if supabase_auth:
        return False
    flash("Supabase Auth is not configured. Check SUPABASE_ANON_KEY.", "error")
    return redirect(url_for(endpoint))


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
        title=f"{APP_NAME} Library | Repository",
    )


@app.route("/resources/<int:resource_id>")
def resource_detail(resource_id: int):
    resource = fetch_resource_by_id(resource_id)
    if not resource:
        abort(404)

    all_resources = fetch_resources(
        "id,title,type,subject,semester,file_url,tags,created_at"
    )
    related = [
        item
        for item in all_resources
        if item.get("id") != resource_id
        and item.get("subject") == resource.get("subject")
    ][:6]
    related = with_resolved_file_urls(related)

    share_url = url_for("resource_detail", resource_id=resource_id, _external=True)

    return render_template(
        "resource_detail.html",
        title=f"{resource.get('title') or 'Resource'} | {APP_NAME}",
        resource=resource,
        related_resources=related,
        share_url=share_url,
    )


@app.route("/upload", methods=["GET", "POST"])
def public_upload():
    if not current_user.is_authenticated:
        flash("Please log in to submit a resource.", "error")
        return redirect(url_for("auth_login"))

    if request.method == "POST":
        validate_csrf_or_abort()

        if require_supabase_or_redirect() or require_blob_storage_or_redirect():
            return redirect(url_for("public_upload"))

        try:
            data = parse_resource_form(request.form, request.files)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("public_upload"))

        if has_duplicate_resource(data["title"], data["subject"], data["semester"]):
            flash("This resource already exists in the library.", "error")
            return redirect(url_for("public_upload"))

        try:
            pending_duplicate = (
                supabase.table("resource_submissions")
                .select("id")
                .eq("title", data["title"])
                .eq("subject", data["subject"])
                .eq("semester", data["semester"])
                .eq("status", "pending")
                .limit(1)
                .execute()
            )
        except Exception as exc:
            flash(f"Could not validate submission uniqueness: {exc}", "error")
            return redirect(url_for("public_upload"))
        if pending_duplicate.data:
            flash("A similar submission is already pending moderation.", "error")
            return redirect(url_for("public_upload"))

        final_file_url = data["file_url"]
        if data["has_upload"]:
            try:
                validate_size_limit(data["upload_file"], PUBLIC_UPLOAD_MAX_BYTES)
                final_file_url = upload_pdf_and_get_public_url(
                    data["upload_file"], data["semester"], data["resource_type"]
                )
            except Exception as exc:
                flash(f"Upload failed: {exc}", "error")
                return redirect(url_for("public_upload"))

        submission = {
            "title": data["title"],
            "type": data["resource_type"],
            "subject": data["subject"],
            "semester": data["semester"],
            "file_url": final_file_url,
            "tags": data["tags"],
            "status": "pending",
            "submitted_by": current_user.id,
        }

        try:
            create_submission(submission)
        except Exception as exc:
            flash(f"Could not save submission: {exc}", "error")
            return redirect(url_for("public_upload"))

        flash("Submission received. Admin will review it shortly.", "success")
        return redirect(url_for("public_upload"))

    return render_template("upload.html", title=f"Submit Resource | {APP_NAME}")


@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))

    auth_redirect = require_auth_client_or_redirect("auth_login")
    if auth_redirect:
        return auth_redirect

    error = None
    if request.method == "POST":
        validate_csrf_or_abort()

        mode = (request.form.get("mode") or "login").strip().lower()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        if not email or not password:
            error = "Email and password are required."
            return render_template(
                "admin/login.html", title=f"{APP_NAME} Auth | Login", error=error
            )

        try:
            if mode == "register":
                supabase_auth.auth.sign_up({"email": email, "password": password})
                flash(
                    "Registration successful. Verify email if required, then log in.",
                    "success",
                )
                return redirect(url_for("auth_login"))

            response = supabase_auth.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            auth_user = getattr(response, "user", None)
            if not auth_user or not getattr(auth_user, "id", None):
                error = "Login failed. Please try again."
                return render_template(
                    "admin/login.html", title=f"{APP_NAME} Auth | Login", error=error
                )

            role = get_user_role(auth_user.id)
            if not role:
                error = "Role not assigned for this account. Contact admin."
                return render_template(
                    "admin/login.html", title=f"{APP_NAME} Auth | Login", error=error
                )

            login_user(AppUser(auth_user.id, role))
            return redirect(url_for("admin"))
        except Exception as exc:
            error = f"Authentication failed: {exc}"

    return render_template(
        "admin/login.html", title=f"{APP_NAME} Auth | Login", error=error
    )


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    validate_csrf_or_abort()
    if supabase_auth:
        try:
            supabase_auth.auth.sign_out()
        except Exception:
            pass
    logout_user()
    return redirect(url_for("auth_login"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if require_role_or_redirect(*MODERATOR_ROLES):
        return redirect(url_for("hello"))

    if request.method == "POST":
        validate_csrf_or_abort()

        if require_supabase_or_redirect():
            return redirect(url_for("admin"))

        try:
            data = parse_resource_form(request.form, request.files)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin"))

        if data["has_upload"] and require_blob_storage_or_redirect():
            return redirect(url_for("admin"))

        try:
            final_file_url = (
                upload_pdf_and_get_public_url(
                    data["upload_file"], data["semester"], data["resource_type"]
                )
                if data["has_upload"]
                else data["file_url"]
            )
        except Exception as exc:
            flash(f"Upload failed: {exc}", "error")
            return redirect(url_for("admin"))

        payload = {
            "title": data["title"],
            "type": data["resource_type"],
            "subject": data["subject"],
            "semester": data["semester"],
            "file_url": final_file_url,
            "tags": data["tags"],
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
    pending_submissions = fetch_submissions("pending")
    reviewed_submissions = fetch_submissions(None, limit=10)
    stats = build_stats(resources)
    return render_template(
        "admin/dashboard.html",
        title=f"{APP_NAME} Admin | Dashboard",
        recent_resources=resolved_resources[:6],
        resources=resolved_resources,
        pending_submissions=pending_submissions,
        reviewed_submissions=reviewed_submissions[:10],
        stats=stats,
    )


@app.route("/admin/submissions/<int:submission_id>/approve", methods=["POST"])
@login_required
def approve_submission(submission_id: int):
    validate_csrf_or_abort()

    if require_role_or_redirect(*MODERATOR_ROLES):
        return redirect(url_for("hello"))

    if require_supabase_or_redirect():
        return redirect(url_for("admin"))

    submission = get_submission_by_id(submission_id)
    if not submission or submission.get("status") != "pending":
        flash("Submission not found or already reviewed.", "error")
        return redirect(url_for("admin"))

    if has_duplicate_resource(
        submission.get("title") or "",
        submission.get("subject") or "",
        int(submission.get("semester") or 0),
    ):
        update_submission(
            submission_id,
            {
                "status": "rejected",
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "reviewed_by": current_user.id,
                "review_note": "Duplicate resource",
            },
        )
        flash("Duplicate detected. Submission rejected.", "error")
        return redirect(url_for("admin"))

    payload = {
        "title": submission.get("title"),
        "type": submission.get("type"),
        "subject": submission.get("subject"),
        "semester": submission.get("semester"),
        "file_url": submission.get("file_url"),
        "tags": submission.get("tags") or [],
        "created_by": submission.get("submitted_by"),
        "approved_by": current_user.id,
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        supabase.table("resources").insert(payload).execute()
    except Exception as exc:
        flash(f"Approval failed: {exc}", "error")
        return redirect(url_for("admin"))

    update_submission(
        submission_id,
        {
            "status": "approved",
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_by": current_user.id,
            "review_note": "Approved and published",
        },
    )

    flash("Submission approved and published.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/submissions/<int:submission_id>/reject", methods=["POST"])
@login_required
def reject_submission(submission_id: int):
    validate_csrf_or_abort()

    if require_role_or_redirect(*MODERATOR_ROLES):
        return redirect(url_for("hello"))

    submission = get_submission_by_id(submission_id)
    if not submission or submission.get("status") != "pending":
        flash("Submission not found or already reviewed.", "error")
        return redirect(url_for("admin"))

    review_note = (request.form.get("review_note") or "").strip()

    update_submission(
        submission_id,
        {
            "status": "rejected",
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_by": current_user.id,
            "review_note": review_note or "Rejected by moderator",
        },
    )

    delete_blob_if_needed(submission.get("file_url") or "")
    flash("Submission rejected.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/resources/<int:resource_id>/delete", methods=["POST"])
@login_required
def delete_resource(resource_id: int):
    validate_csrf_or_abort()

    if require_role_or_redirect("admin"):
        return redirect(url_for("hello"))

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

    delete_blob_if_needed(file_url or "")

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
    if request.path == url_for("public_upload"):
        return redirect(url_for("public_upload")), 413
    return redirect(url_for("auth_login")), 413


@app.errorhandler(500)
def server_error(_err):
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
