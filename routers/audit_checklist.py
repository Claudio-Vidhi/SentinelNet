# -*- coding: utf-8 -*-
"""FastAPI Router per la gestione della Checklist Audit Manutenzione Firewall."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from routers.deps import require_admin
from services import audit_checklist

router = APIRouter(prefix="/api/audit-checklist", tags=["Audit Checklist"])


class CreateEngagementRequest(BaseModel):
    customer_name: str
    tenant: Optional[str] = None
    site_id: Optional[str] = None
    template_id: Optional[int] = None
    assigned_to: Optional[str] = None
    scope_notes: Optional[str] = None
    onsite_or_remote: str = "remote"
    interviewee: Optional[str] = None


class UpdateEngagementMetadataRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    scope_notes: Optional[str] = None
    onsite_or_remote: Optional[str] = None
    interviewee: Optional[str] = None


class UpdateItemAssessmentRequest(BaseModel):
    status: str
    severity: Optional[str] = None
    finding_text: Optional[str] = None
    recommendation_text: Optional[str] = None
    ai_assisted: bool = False


class AddEvidenceRequest(BaseModel):
    item_ref: str
    kind: str
    filename: Optional[str] = None
    path: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    confidential: bool = True


@router.get("/templates")
def list_templates() -> List[Dict[str, Any]]:
    """Elenca tutti i template di audit disponibili."""
    return audit_checklist.list_templates()


@router.get("/templates/{template_id}")
def get_template(template_id: int) -> Dict[str, Any]:
    """Ritorna un template di audit con i relativi item."""
    tpl = audit_checklist.get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Template non trovato")
    return tpl


class TemplateItemRequest(BaseModel):
    ref: Optional[str] = None
    section_no: Optional[int] = None
    section_title: Optional[str] = None
    title: Optional[str] = None
    guidance_why: Optional[str] = None
    guidance_good: Optional[str] = None
    guidance_how: Optional[str] = None
    check_kind: Optional[str] = None
    severity_default: Optional[str] = None
    is_prerequisite: Optional[bool] = None
    requires_evidence: Optional[bool] = None
    sort_order: Optional[int] = None


@router.post("/templates/{template_id}/items", status_code=201)
def create_template_item(
    template_id: int, req: TemplateItemRequest, current_user=Depends(require_admin)
) -> Dict[str, Any]:
    """Aggiunge una domanda al template di audit (solo amministratori)."""
    fields = req.model_dump(exclude_none=True)
    ref = fields.pop("ref", "")
    try:
        return audit_checklist.create_template_item(template_id, ref, **fields)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/templates/{template_id}/items/{ref}")
def update_template_item(
    template_id: int, ref: str, req: TemplateItemRequest, current_user=Depends(require_admin)
) -> Dict[str, Any]:
    """Modifica una domanda del template di audit (solo amministratori)."""
    fields = req.model_dump(exclude_none=True)
    fields.pop("ref", None)
    try:
        return audit_checklist.update_template_item(template_id, ref, **fields)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/templates/{template_id}/items/{ref}")
def delete_template_item(
    template_id: int, ref: str, current_user=Depends(require_admin)
) -> Dict[str, Any]:
    """Elimina una domanda del template, se non e' gia' stata valutata."""
    try:
        return audit_checklist.delete_template_item(template_id, ref)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/engagements")
def list_engagements(
    status: Optional[str] = Query(None), tenant: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    """Elenca gli engagement di audit registrati."""
    return audit_checklist.list_engagements(status=status, tenant=tenant)


@router.post("/engagements", status_code=201)
def create_engagement(req: CreateEngagementRequest) -> Dict[str, Any]:
    """Crea un nuovo audit engagement."""
    try:
        return audit_checklist.create_engagement(
            customer_name=req.customer_name,
            tenant=req.tenant,
            site_id=req.site_id,
            template_id=req.template_id,
            assigned_to=req.assigned_to,
            scope_notes=req.scope_notes,
            onsite_or_remote=req.onsite_or_remote,
            interviewee=req.interviewee,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: int) -> Dict[str, Any]:
    """Ottiene l'engagement completo con tutti gli item e lo stato avanzamento."""
    eng = audit_checklist.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement non trovato")
    return eng


@router.patch("/engagements/{engagement_id}")
def update_engagement_metadata(
    engagement_id: int, req: UpdateEngagementMetadataRequest
) -> Dict[str, Any]:
    """Aggiorna le informazioni generali o lo stato dell'engagement."""
    try:
        return audit_checklist.update_engagement_metadata(
            engagement_id=engagement_id,
            status=req.status,
            assigned_to=req.assigned_to,
            scope_notes=req.scope_notes,
            onsite_or_remote=req.onsite_or_remote,
            interviewee=req.interviewee,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/engagements/{engagement_id}/items/{item_ref}")
def update_item_assessment(
    engagement_id: int, item_ref: str, req: UpdateItemAssessmentRequest
) -> Dict[str, Any]:
    """Salva la valutazione di un singolo item di audit."""
    try:
        return audit_checklist.update_item_assessment(
            engagement_id=engagement_id,
            item_ref=item_ref,
            status=req.status,
            severity=req.severity,
            finding_text=req.finding_text,
            recommendation_text=req.recommendation_text,
            ai_assisted=req.ai_assisted,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/engagements/{engagement_id}/evidence", status_code=201)
def add_evidence(engagement_id: int, req: AddEvidenceRequest) -> Dict[str, Any]:
    """Allega un'evidenza o un riferimento ad un item di audit."""
    try:
        return audit_checklist.add_evidence(
            engagement_id=engagement_id,
            item_ref=req.item_ref,
            kind=req.kind,
            filename=req.filename,
            path=req.path,
            payload=req.payload,
            confidential=req.confidential,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/engagements/{engagement_id}/report")
def get_audit_report(engagement_id: int) -> Response:
    """Genera e restituisce la relazione di audit in formato HTML."""
    try:
        html_content = audit_checklist.generate_audit_relazione(engagement_id)
        return Response(content=html_content, media_type="text/html")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
