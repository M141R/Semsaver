import os
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient, ContentSettings
from supabase import create_client


SUPABASE_PUBLIC_MARKER = "/storage/v1/object/public/"


def extract_supabase_path(file_url: str, bucket_name: str):
    marker = f"{SUPABASE_PUBLIC_MARKER}{bucket_name}/"
    if marker not in file_url:
        return None
    return unquote(file_url.split(marker, 1)[1])


def is_supabase_storage_url(file_url: str):
    parsed = urlparse(file_url or "")
    return "supabase.co" in parsed.netloc and SUPABASE_PUBLIC_MARKER in parsed.path


def main():
    load_dotenv()

    supabase_url = os.environ.get("SUPABASE_URL", "")
    supabase_key = os.environ.get("SUPABASE_KEY", "")
    supabase_bucket = os.environ.get("SUPABASE_STORAGE_BUCKET", "Resources")

    azure_connection = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
    azure_container = os.environ.get("AZURE_STORAGE_CONTAINER", "resources")

    if not supabase_url or not supabase_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required.")
    if not azure_connection:
        raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required.")

    supabase = create_client(supabase_url, supabase_key)
    blob_service = BlobServiceClient.from_connection_string(azure_connection)
    container_client = blob_service.get_container_client(azure_container)

    # Container should already exist, but create if missing for smoother migration.
    try:
        container_client.create_container()
    except Exception:
        pass

    rows = (
        supabase.table("resources")
        .select("id,title,file_url")
        .order("created_at", desc=False)
        .execute()
        .data
        or []
    )

    candidates = [
        row for row in rows if is_supabase_storage_url((row.get("file_url") or ""))
    ]

    print(f"Total rows: {len(rows)}")
    print(f"Rows referencing Supabase Storage: {len(candidates)}")

    migrated = 0
    deleted_old = 0
    skipped = 0
    failed = 0

    for row in candidates:
        row_id = row.get("id")
        old_url = (row.get("file_url") or "").strip()

        try:
            supabase_path = extract_supabase_path(old_url, supabase_bucket)
            if not supabase_path:
                skipped += 1
                print(f"SKIP row={row_id}: could not parse supabase object path")
                continue

            with urlopen(old_url) as response:
                file_bytes = response.read()

            if not file_bytes:
                skipped += 1
                print(f"SKIP row={row_id}: empty download")
                continue

            blob_client = container_client.get_blob_client(supabase_path)
            blob_client.upload_blob(
                file_bytes,
                overwrite=False,
                content_settings=ContentSettings(content_type="application/pdf"),
            )

            new_url = blob_client.url

            supabase.table("resources").update({"file_url": new_url}).eq(
                "id", row_id
            ).execute()
            migrated += 1
            print(f"MIGRATED row={row_id} -> {new_url}")

            try:
                supabase.storage.from_(supabase_bucket).remove([supabase_path])
                deleted_old += 1
                print(f"DELETED_OLD row={row_id} path={supabase_path}")
            except Exception as delete_exc:
                print(f"WARN delete old failed row={row_id}: {delete_exc}")

        except Exception as exc:
            failed += 1
            print(f"FAIL row={row_id}: {exc}")

    print("---")
    print(f"Migrated: {migrated}")
    print(f"Old files deleted: {deleted_old}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    main()
