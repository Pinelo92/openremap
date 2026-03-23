"""
Tuning router — accepts .bin and .ori files, returns ECU identification or a cooked recipe.
Also exposes patcher endpoints for validating and applying recipes to ECU binaries.
"""

import base64
import json

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response

from api.core.limiter import ApiLimits, limiter
from openremap.tuning.manufacturers import EXTRACTORS
from openremap.tuning.schemas.analyzer import (
    AnalyzerResponseSchema,
    ECUIdentitySchema,
    SupportedFamiliesResponseSchema,
    SupportedFamilySchema,
)
from openremap.tuning.schemas.patcher import (
    ExistenceSummarySchema,
    MissingInstructionSchema,
    PatchApplyResponseSchema,
    PatchedFailureSchema,
    PatchedSummarySchema,
    PatcherWarningsSchema,
    PatchFailedInstructionSchema,
    PatchSummarySchema,
    ShiftedInstructionSchema,
    StrictSummarySchema,
    ValidateExistsResponseSchema,
    ValidatePatchedResponseSchema,
    ValidateStrictResponseSchema,
)
from openremap.tuning.services.identifier import identify_ecu
from openremap.tuning.services.recipe_builder import ECUDiffAnalyzer
from openremap.tuning.services.patcher import ECUPatcher
from openremap.tuning.services.validate_exists import ECUExistenceValidator, MatchStatus
from openremap.tuning.services.validate_patched import ECUPatchedValidator
from openremap.tuning.services.validate_strict import ECUStrictValidator

router = APIRouter()

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = (".bin", ".ori")


def _is_allowed(filename: str) -> bool:
    return filename.lower().endswith(ALLOWED_EXTENSIONS)


def _warnings(
    size_warn: str | None,
    match_key_warn: str | None = None,
) -> PatcherWarningsSchema:
    return PatcherWarningsSchema(
        size_mismatch=bool(size_warn),
        size_mismatch_detail=size_warn or None,
        match_key_mismatch=bool(match_key_warn),
        match_key_mismatch_detail=match_key_warn or None,
    )


# ---------------------------------------------------------------------------
# Tuning endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/supported-families",
    response_model=SupportedFamiliesResponseSchema,
    summary="List all supported ECU families",
    description=(
        "Returns every ECU family the analyzer can currently identify. "
        "Families not in this list will be returned as 'Unknown manufacturer'. "
        "Use this to check coverage before submitting a binary."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.READ)
async def get_supported_families(request: Request) -> SupportedFamiliesResponseSchema:
    families: list[SupportedFamilySchema] = []

    for extractor in EXTRACTORS:
        for family in extractor.supported_families:
            families.append(
                SupportedFamilySchema(
                    manufacturer=extractor.name,
                    family=family,
                    extractor=extractor.__class__.__name__,
                )
            )

    return SupportedFamiliesResponseSchema(
        total=len(families),
        families=families,
    )


@router.post(
    "/cook",
    response_model=AnalyzerResponseSchema,
    summary="Cook a recipe from two ECU binary files",
    description=(
        "Upload an original and a modified ECU .bin or .ori file. "
        "Diffs the two binaries and returns a JSON recipe containing all changes "
        "with context patterns, ECU identification, and statistics. Ready for MongoDB storage."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.WRITE)
async def cook_recipe(
    request: Request,
    original: UploadFile = File(..., description="The original ECU .bin or .ori file"),
    modified: UploadFile = File(..., description="The modified ECU .bin or .ori file"),
) -> AnalyzerResponseSchema:
    for upload in (original, modified):
        filename = upload.filename or ""
        if not _is_allowed(filename):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"File '{filename}' is not a .bin or .ori file.",
            )

    original_bytes = await original.read()
    modified_bytes = await modified.read()

    for name, data in (
        (original.filename, original_bytes),
        (modified.filename, modified_bytes),
    ):
        if len(data) == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"File '{name}' is empty.",
            )
        if len(data) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File '{name}' exceeds the 10 MB limit.",
            )

    try:
        analyzer = ECUDiffAnalyzer(
            original_data=original_bytes,
            modified_data=modified_bytes,
            original_filename=original.filename or "original.bin",
            modified_filename=modified.filename or "modified.bin",
            context_size=32,
        )
        recipe = analyzer.build_recipe()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cook failed: {exc}",
        )

    return AnalyzerResponseSchema(**recipe)


@router.post(
    "/identify",
    response_model=ECUIdentitySchema,
    summary="Identify a single ECU binary file",
    description=(
        "Upload a single ECU .bin or .ori file. "
        "Returns the lean ECU identity: manufacturer, match key, ECU family, "
        "variant, software version, file size, and full-file SHA-256. "
        "No modified file needed — useful for checking what ECU a file belongs to "
        "before creating or applying a recipe."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.WRITE)
async def identify_ecu_file(
    request: Request,
    file: UploadFile = File(..., description="The ECU .bin or .ori file to identify"),
) -> ECUIdentitySchema:
    filename = file.filename or ""
    if not _is_allowed(filename):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File '{filename}' is not a .bin or .ori file.",
        )

    data = await file.read()

    if len(data) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File '{filename}' is empty.",
        )
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File '{filename}' exceeds the 10 MB limit.",
        )

    try:
        result = identify_ecu(data=data, filename=filename)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Identification failed: {exc}",
        )

    return ECUIdentitySchema(**result)


# ---------------------------------------------------------------------------
# Patcher shared helpers
# ---------------------------------------------------------------------------


async def _read_bin(upload: UploadFile, label: str) -> bytes:
    filename = upload.filename or ""
    if not _is_allowed(filename):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{label} file '{filename}' must be a .bin or .ori file.",
        )
    data = await upload.read()
    if not data:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{label} file '{filename}' is empty.",
        )
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{label} file '{filename}' exceeds the 10 MB limit.",
        )
    return data


async def _read_recipe(upload: UploadFile) -> dict:
    filename = upload.filename or "recipe.json"
    if not filename.lower().endswith(".json"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Recipe file '{filename}' must be a .json file. "
                "Check that you are sending the binary to the 'target' field "
                "and the recipe to the 'recipe' field."
            ),
        )
    raw = await upload.read()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Recipe file '{filename}' is empty.",
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Recipe file '{filename}' is not valid UTF-8: {exc}",
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Recipe file '{filename}' is not valid JSON: {exc}",
        )


# ---------------------------------------------------------------------------
# POST /patch/validate/strict
# ---------------------------------------------------------------------------


@router.post(
    "/patch/validate/strict",
    response_model=ValidateStrictResponseSchema,
    summary="Strict offset validation — verify ob bytes before patching",
    description=(
        "Reads the exact offset of every recipe instruction and compares the "
        "original bytes (ob) against what is actually in the binary. "
        "All instructions are checked before reporting. "
        "Returns safe_to_patch=true only when every instruction passes. "
        "Run this before /patch/apply."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.WRITE)
async def validate_strict(
    request: Request,
    target: UploadFile = File(
        ..., description="The original (unpatched) ECU .bin file"
    ),
    recipe: UploadFile = File(..., description="The recipe .json file"),
) -> ValidateStrictResponseSchema:
    target_data = await _read_bin(target, "Target")
    recipe_dict = await _read_recipe(recipe)

    try:
        validator = ECUStrictValidator(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target.filename or "target.bin",
            recipe_name=recipe.filename or "recipe.json",
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.validate_all()
        report = validator.to_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Strict validation failed: {exc}",
        )

    return ValidateStrictResponseSchema(
        target_file=report["target_file"],
        target_md5=report["target_md5"],
        warnings=_warnings(size_warn, match_key_warn),
        summary=StrictSummarySchema(**report["summary"]),
    )


# ---------------------------------------------------------------------------
# POST /patch/validate/exists
# ---------------------------------------------------------------------------


@router.post(
    "/patch/validate/exists",
    response_model=ValidateExistsResponseSchema,
    summary="Existence validation — search entire binary for ob bytes",
    description=(
        "Searches the entire binary for the original bytes (ob) of every instruction "
        "and classifies each as EXACT, SHIFTED, or MISSING. "
        "Run this after a strict validation failure to understand why it failed — "
        "shifted means a SW revision moved the map; missing means the wrong ECU."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.WRITE)
async def validate_exists(
    request: Request,
    target: UploadFile = File(..., description="The target ECU .bin file"),
    recipe: UploadFile = File(..., description="The recipe .json file"),
) -> ValidateExistsResponseSchema:
    target_data = await _read_bin(target, "Target")
    recipe_dict = await _read_recipe(recipe)

    try:
        validator = ECUExistenceValidator(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target.filename or "target.bin",
            recipe_name=recipe.filename or "recipe.json",
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.validate_all()
        report = validator.to_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Existence validation failed: {exc}",
        )

    shifted = [
        ShiftedInstructionSchema(
            index=r["instruction_index"],
            expected_offset=r["offset_hex_expected"],
            found_offset=r["closest_offset"] or "",
            shift=r["shift"] or 0,
            match_count=len(r["offsets_found"]),
        )
        for r in report["results"]
        if r["status"] == MatchStatus.SHIFTED.value
    ]

    missing = [
        MissingInstructionSchema(
            index=r["instruction_index"],
            expected_offset=r["offset_hex_expected"],
            size=r["size"],
        )
        for r in report["results"]
        if r["status"] == MatchStatus.MISSING.value
    ]

    return ValidateExistsResponseSchema(
        target_file=report["target_file"],
        target_md5=report["target_md5"],
        warnings=_warnings(size_warn, match_key_warn),
        summary=ExistenceSummarySchema(**report["summary"]),
        shifted=shifted,
        missing=missing,
    )


# ---------------------------------------------------------------------------
# POST /patch/validate/patched
# ---------------------------------------------------------------------------


@router.post(
    "/patch/validate/patched",
    response_model=ValidatePatchedResponseSchema,
    summary="Post-patch verification — confirm mb bytes were written correctly",
    description=(
        "Reads the exact offset of every instruction in a patched binary and confirms "
        "that the modified bytes (mb) are now present there. "
        "Mirror image of /patch/validate/strict: strict checks ob before; this checks mb after. "
        "Returns patch_confirmed=true only when every instruction passes."
    ),
    status_code=status.HTTP_200_OK,
)
@limiter.limit(ApiLimits.WRITE)
async def validate_patched(
    request: Request,
    patched: UploadFile = File(..., description="The patched ECU .bin file"),
    recipe: UploadFile = File(
        ..., description="The recipe .json file used during patching"
    ),
) -> ValidatePatchedResponseSchema:
    patched_data = await _read_bin(patched, "Patched")
    recipe_dict = await _read_recipe(recipe)

    try:
        validator = ECUPatchedValidator(
            patched_data=patched_data,
            recipe=recipe_dict,
            patched_name=patched.filename or "patched.bin",
            recipe_name=recipe.filename or "recipe.json",
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.verify_all()
        report = validator.to_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patched validation failed: {exc}",
        )

    failures = [
        PatchedFailureSchema(
            index=r["instruction_index"],
            offset=f"0x{r['offset_hex']}",
            size=r["size"],
            reason=r["reason"],
        )
        for r in report["all_results"]
        if not r["passed"]
    ]

    # Remap summary keys: service uses "passed", schema uses "confirmed"
    raw_summary = report["summary"]
    summary = PatchedSummarySchema(
        total=raw_summary["total"],
        confirmed=raw_summary["passed"],
        failed=raw_summary["failed"],
        patch_confirmed=raw_summary["patch_confirmed"],
    )

    return ValidatePatchedResponseSchema(
        patched_file=report["patched_file"],
        patched_md5=report["patched_md5"],
        warnings=_warnings(size_warn, match_key_warn),
        summary=summary,
        failures=failures,
    )


# ---------------------------------------------------------------------------
# POST /patch/apply
# ---------------------------------------------------------------------------


@router.post(
    "/patch/apply",
    summary="Apply a recipe to a target ECU binary",
    description=(
        "Runs strict pre-flight validation then applies every instruction using a "
        "ctx+ob anchor search within ±2 KB of the expected offset. "
        "On success, returns the patched binary as application/octet-stream. "
        "A compact patch report is attached in the X-Patch-Report response header "
        "as base64-encoded JSON. "
        "On failure, returns 422 with a plain-text error explaining which instructions failed. "
        "Remember: correct checksums with ECM Titanium / WinOLS before flashing."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "content": {"application/octet-stream": {}},
            "description": "Patched binary file.",
        },
        422: {
            "description": "Validation or patch failure — no file written.",
        },
    },
)
@limiter.limit(ApiLimits.WRITE)
async def patch_apply(
    request: Request,
    target: UploadFile = File(
        ..., description="The original (unpatched) ECU .bin file"
    ),
    recipe: UploadFile = File(..., description="The recipe .json file"),
) -> Response:
    target_data = await _read_bin(target, "Target")
    recipe_dict = await _read_recipe(recipe)

    target_name = target.filename or "target.bin"

    # Compute size and match-key warnings before the patcher runs.
    # These are informational — the patcher's strict validator is the real gate.
    _preflight = ECUStrictValidator(
        target_data=target_data,
        recipe=recipe_dict,
        target_name=target_name,
        recipe_name=recipe.filename or "recipe.json",
    )
    size_warn = _preflight.check_file_size()
    match_key_warn = _preflight.check_match_key()

    try:
        patcher = ECUPatcher(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target_name,
            recipe_name=recipe.filename or "recipe.json",
            skip_validation=False,
        )
        patched_bytes = patcher.apply_all()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patch failed unexpectedly: {exc}",
        )

    raw_report = patcher.to_dict(patched_data=patched_bytes)
    raw_summary = raw_report["summary"]

    patch_report = PatchApplyResponseSchema(
        target_file=raw_report["target_file"],
        target_md5=raw_report["target_md5"],
        warnings=_warnings(size_warn, match_key_warn),
        summary=PatchSummarySchema(
            total=raw_summary["total"],
            applied=raw_summary["success"],
            failed=raw_summary["failed"],
            shifted=raw_summary["shifted"],
            patch_applied=raw_summary["patch_applied"],
            patched_md5=raw_summary.get("patched_md5"),
        ),
        failures=[
            PatchFailedInstructionSchema(
                index=r["index"],
                offset=r["offset_expected_hex"],
                message=r["message"],
            )
            for r in raw_report["results"]
            if r["status"] == "failed"
        ],
    )

    report_b64 = base64.b64encode(
        patch_report.model_dump_json().encode("utf-8")
    ).decode("ascii")

    stem = target_name.rsplit(".", 1)[0]

    return Response(
        content=patched_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{stem}_patched.bin"',
            "X-Patch-Report": report_b64,
        },
    )
