import shutil
import datetime
from pathlib import Path

# Default database locations (adjust if needed)
BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = BASE_DIR / "phishing_db.sqlite"
DEFAULT_BACKUP_DIR = BASE_DIR

def backup_phishing_db(src: Path = DEFAULT_DB_PATH, backup_dir: Path = DEFAULT_BACKUP_DIR) -> Path:
    """Create a timestamped backup of the phishing SQLite database.

    Args:
        src: Path to the source SQLite file.
        backup_dir: Directory where the backup file will be stored.

    Returns:
        Path to the created backup file.
    """
    if not src.exists():
        raise FileNotFoundError(f"Source database not found: {src}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"phishing_db_backup_{timestamp}.sqlite"
    backup_path = backup_dir / backup_name
    shutil.copy2(src, backup_path)
    return backup_path

def restore_phishing_db(backup_file: Path, target: Path = DEFAULT_DB_PATH) -> None:
    """Restore the phishing SQLite database from a backup file.

    Args:
        backup_file: Path to the backup SQLite file.
        target: Destination path where the database will be restored.
    """
    if not backup_file.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_file}")
    # Ensure target directory exists
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_file, target)
