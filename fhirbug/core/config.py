"""Configuration and wordlist management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

WORDLIST_DIR = Path(__file__).parent.parent / "wordlists"

# R4 resource types — the full set per the spec
FHIR_R4_RESOURCES = [
    "Account", "ActivityDefinition", "AdverseEvent", "AllergyIntolerance",
    "Appointment", "AppointmentResponse", "AuditEvent", "Basic", "Binary",
    "BiologicallyDerivedProduct", "BodyStructure", "Bundle",
    "CapabilityStatement", "CarePlan", "CareTeam", "CatalogEntry",
    "ChargeItem", "ChargeItemDefinition", "Claim", "ClaimResponse",
    "ClinicalImpression", "CodeSystem", "Communication",
    "CommunicationRequest", "CompartmentDefinition", "Composition",
    "ConceptMap", "Condition", "Consent", "Contract", "Coverage",
    "CoverageEligibilityRequest", "CoverageEligibilityResponse",
    "DetectedIssue", "Device", "DeviceDefinition", "DeviceMetric",
    "DeviceRequest", "DeviceUseStatement", "DiagnosticReport",
    "DocumentManifest", "DocumentReference", "EffectEvidenceSynthesis",
    "Encounter", "Endpoint", "EnrollmentRequest", "EnrollmentResponse",
    "EpisodeOfCare", "EventDefinition", "Evidence", "EvidenceVariable",
    "ExampleScenario", "ExplanationOfBenefit", "FamilyMemberHistory",
    "Flag", "Goal", "GraphDefinition", "Group", "GuidanceResponse",
    "HealthcareService", "ImagingStudy", "Immunization",
    "ImmunizationEvaluation", "ImmunizationRecommendation",
    "ImplementationGuide", "InsurancePlan", "Invoice", "Library",
    "Linkage", "List", "Location", "Measure", "MeasureReport", "Media",
    "Medication", "MedicationAdministration", "MedicationDispense",
    "MedicationKnowledge", "MedicationRequest", "MedicationStatement",
    "MedicinalProduct", "MedicinalProductAuthorization",
    "MedicinalProductContraindication", "MedicinalProductIndication",
    "MedicinalProductIngredient", "MedicinalProductInteraction",
    "MedicinalProductManufactured", "MedicinalProductPackaged",
    "MedicinalProductPharmaceutical", "MedicinalProductUndesirableEffect",
    "MessageDefinition", "MessageHeader", "MolecularSequence",
    "NamingSystem", "NutritionOrder", "Observation",
    "ObservationDefinition", "OperationDefinition", "OperationOutcome",
    "Organization", "OrganizationAffiliation", "Parameters", "Patient",
    "PaymentNotice", "PaymentReconciliation", "Person", "PlanDefinition",
    "Practitioner", "PractitionerRole", "Procedure", "Provenance",
    "Questionnaire", "QuestionnaireResponse", "RelatedPerson",
    "RequestGroup", "ResearchDefinition", "ResearchElementDefinition",
    "ResearchStudy", "ResearchSubject", "RiskAssessment",
    "RiskEvidenceSynthesis", "Schedule", "SearchParameter",
    "ServiceRequest", "Slot", "Specimen", "SpecimenDefinition",
    "StructureDefinition", "StructureMap", "Subscription",
    "SubstanceSpecification", "SupplyDelivery", "SupplyRequest", "Task",
    "TerminologyCapabilities", "TestReport", "TestScript", "ValueSet",
    "VerificationResult", "VisionPrescription",
]

# High-value resources for PHI exfiltration
PHI_RESOURCES = [
    "Patient", "Encounter", "Observation", "DiagnosticReport",
    "Condition", "Procedure", "MedicationRequest", "MedicationStatement",
    "AllergyIntolerance", "Immunization", "DocumentReference",
    "CarePlan", "CareTeam", "FamilyMemberHistory", "Goal",
    "ClinicalImpression", "Consent", "ExplanationOfBenefit",
    "Coverage", "Claim", "Person", "RelatedPerson",
]

# Common search parameters that accept string input — injection candidates
INJECTABLE_SEARCH_PARAMS = [
    "name", "family", "given", "address", "address-city",
    "address-state", "address-postalcode", "telecom", "email", "phone",
    "identifier", "text", "title", "_content", "_text", "_filter",
    "_query", "value", "code-value-string",
]

# Special search parameters worth testing
SPECIAL_SEARCH_PARAMS = [
    "_id", "_lastUpdated", "_tag", "_profile", "_security",
    "_source", "_text", "_content", "_list", "_has", "_type",
    "_sort", "_count", "_include", "_revinclude", "_summary",
    "_total", "_elements", "_contained", "_containedType",
    "_score", "_filter", "_query", "_format", "_pretty",
]

# FHIR Operations that may be exposed
FHIR_OPERATIONS = [
    "$validate", "$meta", "$meta-add", "$meta-delete",
    "$convert", "$graphql", "$everything", "$match",
    "$merge", "$members", "$document", "$translate",
    "$lookup", "$expand", "$subsumes", "$closure",
    "$evaluate", "$evaluate-measure", "$data-requirements",
    "$submit-data", "$collect-data", "$care-gaps",
    "$apply", "$process-message", "$transform",
    "$export", "$import", "$reindex",
    "$purge", "$expunge", "$diff",
]

# SMART on FHIR scopes to probe
SMART_SCOPES = [
    "patient/*.read", "patient/*.write", "patient/*.*",
    "user/*.read", "user/*.write", "user/*.*",
    "system/*.read", "system/*.write", "system/*.*",
    "launch", "launch/patient", "launch/encounter",
    "openid", "fhirUser", "profile",
    "offline_access", "online_access",
]


@dataclass
class TargetConfig:
    base_url: str
    access_token: str = ""
    client_id: str = ""
    client_secret: str = ""
    timeout: float = 30.0
    max_concurrent: int = 10
    rate_limit: float = 0.1  # seconds between requests
    verify_ssl: bool = True
    proxy: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    resources_to_test: list[str] = field(default_factory=list)

    @property
    def auth_headers(self) -> dict[str, str]:
        h = dict(self.headers)
        h.setdefault("Accept", "application/fhir+json")
        if self.access_token:
            h["Authorization"] = f"Bearer {self.access_token}"
        return h

    def metadata_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/metadata"

    def resource_url(self, resource_type: str, resource_id: str = "") -> str:
        url = f"{self.base_url.rstrip('/')}/{resource_type}"
        if resource_id:
            url += f"/{resource_id}"
        return url
