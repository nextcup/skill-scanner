# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""ZIP file downloader and extractor for remote skill packages."""

from __future__ import annotations

import io
import logging
import os
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from .exceptions import SkillLoadError

logger = logging.getLogger(__name__)


class ZipDownloader:
    """Downloads and extracts skill packages from ZIP files and URLs.

    Uses system temporary directories for storage, which are automatically
    cleaned up after scanning.
    """

    def __init__(self, connect_timeout: float = 30.0):
        """
        Initialize ZipDownloader.

        Args:
            connect_timeout: Connection timeout in seconds for URL downloads.
        """
        self.connect_timeout = connect_timeout

    def download_and_extract(self, url: str) -> Path:
        """
        Download a ZIP file from URL and extract it to a temporary directory.

        Args:
            url: HTTP/HTTPS URL pointing to a ZIP file.

        Returns:
            Path to the directory containing the extracted contents.

        Raises:
            SkillLoadError: If download fails or file is not a valid ZIP.
        """
        if not url.startswith(("http://", "https://")):
            raise SkillLoadError(f"Invalid URL: {url}")

        # Download to a temporary ZIP file
        zip_path = tempfile.mktemp(suffix=".zip")
        try:
            try:
                with urllib.request.urlopen(url, timeout=self.connect_timeout) as response:
                    zip_data: bytes = response.read()
                with open(zip_path, 'wb') as f:
                    f.write(zip_data)
            except Exception as e:
                raise SkillLoadError(f"Failed to download {url}: {e}") from e

            # Extract the ZIP
            temp_dir = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Security check: validate it's a real ZIP
                    if not zipfile.is_zipfile(zip_path):
                        raise SkillLoadError(f"Downloaded file is not a valid ZIP: {url}")

                    # Extract with basic path traversal protection
                    for member in zf.namelist():
                        member_path = Path(member)
                        # Reject paths with traversal sequences
                        if member_path.parts and any(p == '..' for p in member_path.parts):
                            logger.warning(f"Skipping path traversal attempt: {member}")
                            continue
                        zf.extract(member, temp_dir)

            except zipfile.BadZipFile as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise SkillLoadError(f"Invalid ZIP file from {url}: {e}") from e

            return Path(temp_dir)

        finally:
            # Clean up the temporary ZIP file
            Path(zip_path).unlink(missing_ok=True)

    def extract_zip(self, zip_path: Path | str) -> Path:
        """
        Extract a local ZIP file to a temporary directory.

        Args:
            zip_path: Path to a local ZIP file.

        Returns:
            Path to the directory containing the extracted contents.

        Raises:
            SkillLoadError: If the file is not a valid ZIP.
        """
        zip_path = Path(zip_path)

        if not zip_path.exists():
            raise SkillLoadError(f"ZIP file not found: {zip_path}")

        if not zipfile.is_zipfile(zip_path):
            raise SkillLoadError(f"Not a valid ZIP file: {zip_path}")

        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Security check: path traversal protection
                for member in zf.namelist():
                    member_path = Path(member)
                    if member_path.parts and any(p == '..' for p in member_path.parts):
                        logger.warning(f"Skipping path traversal attempt: {member}")
                        continue
                    zf.extract(member, temp_dir)

            return Path(temp_dir)

        except zipfile.BadZipFile as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise SkillLoadError(f"Invalid ZIP file {zip_path}: {e}") from e

    def cleanup(self, path: Path | str) -> None:
        """
        Recursively delete a temporary directory.

        Args:
            path: Path to directory to delete.
        """
        path = Path(path)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)