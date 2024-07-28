# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4package.metadata import Metadata
from lib4sbom.data.package import SBOMPackage
from lib4sbom.parser import SBOMParser
from packageurl import PackageURL

# from semantic_versioning import SemanticVersion
from packaging.version import InvalidVersion, parse


class SBOMdebt:
    def __init__(self, sbom, options={}, output=""):
        self.sbom = sbom
        self.options = options
        self.output = output
        self.package_count = 0
        self.package_count_debt = 0
        self.package = []
        self.update_count = self.options.get("updates", 2)
        self.debug = self.options.get("debug", False)
        self.verbose = self.options.get("verbose", False)
        self.debt = {}

    def get_package_info(self, package_name, package_type, version):
        package_metadata = Metadata(package_type)
        package_metadata.get_package(package_name)
        package_info = package_metadata.get_data()
        if self.debug:
            package_metadata.print_data()
        package_updates = []
        if self.verbose:
            print(f"Package - {package_name} {version}")
        tag_count = 0
        first_tag = None
        if len(package_info) > 0:
            if "tags" in package_info["repo_metadata"]:
                for release in package_info["repo_metadata"]["tags"]:
                    name = release["name"].lower().replace("version-", "").replace("v", "")
                    if first_tag is None:
                        first_tag = name
                    date = release["published_at"]
                    if version == name:
                        if self.debug:
                            print(f"Found version - {name} = {version} [{tag_count}]")
                        break
                    tag_count += 1
                    package_updates.append([name, date])
                # if tag_count > self.update_count:
                #     for u in package_updates:
                #         print (u)
            elif self.debug:
                print(f"[ERROR] - No version history available for {package_name}")
            latest_version = package_metadata.get_latest_version()
            if first_tag is not None and first_tag != latest_version:
                if self.debug:
                    print(
                        f"Latest version {latest_version} differs from latest tag {first_tag}"
                    )
                try:
                    if parse(latest_version) < parse(first_tag):
                        latest_version = first_tag
                except InvalidVersion:
                    if self.debug:
                        print(f"Invalid version for {package_name}")

            latest_date = package_metadata.get_latest_release_time()
            updates = package_metadata.get_no_of_updates(version)
        else:
            # No data available
            latest_version = version
            latest_date = None
            updates = 0
            package_updates = 0
        return latest_version, latest_date, updates, package_updates

    def calculate(self):
        # Set up SBOM parser
        sbom_parser = SBOMParser()
        # Load SBOM - will autodetect SBOM type
        sbom_parser.parse_file(self.sbom)
        if self.debug:
            print(f"Parsed {self.sbom}")
        pack = SBOMPackage()
        for p in sbom_parser.get_packages():
            self.package_count += 1
            pack.initialise()
            pack.copy_package(p)
            purl = pack.get_purl()
            if purl is not None:
                if self.debug:
                    print(f"Processing {purl}")
                purl_info = PackageURL.from_string(purl).to_dict()
                (
                    latest_version,
                    latest_date,
                    updates,
                    package_updates,
                ) = self.get_package_info(
                    purl_info["name"], purl_info["type"], purl_info["version"]
                )
                if updates > self.update_count:
                    self.package_count_debt += 1
                    if self.debug:
                        print(f"{purl_info['name']}: {updates} updates available")
                        print(
                            f"Latest version {latest_version} released on {latest_date}."
                        )
                    element = {}
                    element["name"] = purl_info["name"]
                    element["current_version"] = purl_info["version"]
                    element["latest_version"] = latest_version
                    element["latest_date"] = latest_date
                    element["updates"] = updates
                    if self.verbose:
                        element["package_updates"] = package_updates
                    self.package.append(element)
                elif updates == 0 and latest_version != purl_info["version"]:
                    if self.debug and self.options.get("verbose", False):
                        print(
                            f"Version mismatch for {purl_info['name']}."
                            f" Current version {purl_info['version']}."
                            f" Latest version {latest_version}"
                        )
            elif self.debug:
                print(f"Unable to process {pack.get_name()}")
        # Capture summary
        self.debt["sbom"] = self.sbom
        self.debt["packages"] = self.package
        self.debt["package_count"] = self.package_count
        self.debt["debt_count"] = self.package_count_debt
        self.debt["ratio"] = self.package_count_debt / self.package_count

    def get_debt(self):
        return self.debt
