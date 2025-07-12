from packaging import version
# ------------- VERSION RANGE CHECK -------------
def is_version_vulnerable(detected_version, cve_entry):
    try:
        dv = version.parse(detected_version)
        start_incl = cve_entry.get("versionStartIncluding")
        start_excl = cve_entry.get("versionStartExcluding")
        end_incl = cve_entry.get("versionEndIncluding")
        end_excl = cve_entry.get("versionEndExcluding")

        if start_incl and dv < version.parse(start_incl):
            return False
        if start_excl and dv <= version.parse(start_excl):
            return False
        if end_incl and dv > version.parse(end_incl):
            return False
        if end_excl and dv >= version.parse(end_excl):
            return False

        if not any([start_incl, start_excl, end_incl, end_excl]):
            return detected_version == cve_entry.get("version") or cve_entry.get("version") == "*"

        return True
    except Exception:
        return False