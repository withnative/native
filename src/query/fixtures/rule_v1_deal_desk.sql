-- PROPOSED first explicit-facet subset, not the historical corpus contract.
-- deal: One, ?1 Argument deal_id:string, canonical integer discount_bp.
SELECT r.id AS id, d.value AS discount_bp
FROM records r
JOIN facet_values d ON d.record_id=r.id AND d.key='discount_bp'
WHERE r.id=?1
ORDER BY r.id, d.record_id, d.key;

-- policies: Many, ?1 deal_id, captured NowMs filtering happens in CEL over
-- validated canonical integer fields. '*' is a stored wildcard facet value.
SELECT r.id AS id, b.value AS base_cap, a.value AS appr_cap,
       ef.value AS effective_from_ms, et.value AS effective_to_ms
FROM records r
JOIN facet_values b ON b.record_id=r.id AND b.key='base_cap_bp'
JOIN facet_values a ON a.record_id=r.id AND a.key='approval_cap_bp'
JOIN facet_values ef ON ef.record_id=r.id AND ef.key='effective_from_ms'
JOIN facet_values et ON et.record_id=r.id AND et.key='effective_to_ms'
JOIN facet_values ps ON ps.record_id=r.id AND ps.key='segment'
JOIN facet_values pr ON pr.record_id=r.id AND pr.key='region'
JOIN facet_values ds ON ds.record_id=?1 AND ds.key='segment'
JOIN facet_values dr ON dr.record_id=?1 AND dr.key='region'
WHERE r.type='ConcessionPolicy'
  AND (ps.value='"*"' OR ps.value=ds.value)
  AND (pr.value='"*"' OR pr.value=dr.value)
ORDER BY ((ps.value!='"*"')+(pr.value!='"*"')) DESC, r.id,
         b.record_id,b.key,a.record_id,a.key,ef.record_id,ef.key,
         et.record_id,et.key,ps.record_id,ps.key,pr.record_id,pr.key,
         ds.record_id,ds.key,dr.record_id,dr.key;

-- approvals: Many, ?1 deal_id, canonical integer cap/expiry, link composite
-- retained as a non-null composite even if CEL only uses approval id.
SELECT r.id AS id, l.source_id AS source_id, l.target_id AS target_id, l.relationship AS relationship, c.value AS cap_bp, e.value AS expires_at_ms
FROM records r
JOIN links l ON l.source_id=r.id
JOIN facet_values c ON c.record_id=r.id AND c.key='cap_bp'
JOIN facet_values e ON e.record_id=r.id AND e.key='expires_at_ms'
WHERE r.type='Approval' AND l.target_id=?1 AND l.relationship='approval_for'
ORDER BY r.id,l.source_id,l.target_id,l.relationship,c.record_id,c.key,e.record_id,e.key;
